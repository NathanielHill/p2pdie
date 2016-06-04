#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <unistd.h>
#include <pcap/bpf.h>
#include <net/if.h>
#if defined( __FreeBSD__ )
#include <net/ethernet.h>
#elif defined( __NetBSD__ )
#include <net/if_ether.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <gtk/gtk.h>

#define BUFFER       ( 131072 )
#define LIFETIME     ( 300 )  // timeout for hosts and connections
#define TIMEOUT      ( 10 )   // timeout for syn and fin
#define SYN_WAIT     ( 0 )
#define ESTABLISHED  ( 1 )
#define FIN_WAIT     ( 2 )

struct tcpsum
{
   struct in_addr ip_src;
   struct in_addr ip_dst;
   char zero;
   unsigned char ip_p;
   unsigned short len;
};

struct conn
{
   unsigned int state, timeout, new;
   unsigned int in, out;
   int snipe;
};

struct connkey
{
   struct in_addr addr;
   unsigned short sport, dport;
};

struct host
{
   unsigned int alive, new;
   GtkTreeIter iter;
   GHashTable *conns;
   int snipe;
};

struct session
{
   int bpf;
   char if_name[IFNAMSIZ];
   struct in_addr if_addr;
   struct in_addr if_mask;
   struct in_addr if_net;
   unsigned int len;
   void *buff;
   GHashTable *hosts;
   GtkTreeStore *store;
   int updateid, ioid, killin;
};

unsigned char aim_bits[] =
{
   0x00, 0x00,
   0xC0, 0x07,
   0x30, 0x19,
   0x08, 0x21,
   0x04, 0x41,
   0x84, 0x43, 
   0x02, 0x81,
   0x22, 0x89,
   0xFE, 0xFF,
   0x22, 0x89,
   0x02, 0x81,
   0x84, 0x43, 
   0x04, 0x41,
   0x08, 0x21,
   0x30, 0x19,
   0xC0, 0x07
};

unsigned char aim_mask[] =
{
   0x00, 0x00,
   0xC0, 0x07,
   0x30, 0x19,
   0x08, 0x21,
   0x04, 0x41,
   0x84, 0x43, 
   0x02, 0x81,
   0x22, 0x89,
   0xFE, 0xFF,
   0x22, 0x89,
   0x02, 0x81,
   0x84, 0x43, 
   0x04, 0x41,
   0x08, 0x21,
   0x30, 0x19,
   0xC0, 0x07
};

GdkCursor *aim_cursor = NULL;

// this only works on little endian??
// returns checksum in network order??
unsigned short in_cksum( const void *buf, int len )
{
   const unsigned short *data = buf;
   unsigned int sum = 0;

   while( len > 1 )
   {
      sum += *data++;
      len -= 2;
   }
   if( len == 1 )
      sum += *(unsigned char *)data;
   sum = ( sum >> 16 ) + ( sum & 0xFFFF );
   sum += sum >> 16;
   return ~sum;
}

void free_host( struct host *cur )
{
   g_hash_table_destroy( cur->conns );
   free( cur );
}

guint hash_connkey( struct connkey *key )
{
   return key->addr.s_addr + key->sport + key->dport;
}

gboolean eq_connkey( struct connkey *lhs, struct connkey *rhs )
{
   return lhs->addr.s_addr == rhs->addr.s_addr && lhs->sport == rhs->sport
      && lhs->dport == rhs->dport;
}

struct host *lookup_host( struct session *ses, struct in_addr addr )
{
   return g_hash_table_lookup( ses->hosts, (gpointer)addr.s_addr );
}

struct host *get_host( struct session *ses, struct in_addr addr )
{
   struct host *cur = g_hash_table_lookup( ses->hosts, (gpointer)addr.s_addr );

   if( cur == NULL )
   {
      if(( cur = malloc( sizeof( struct host ))) == NULL )
         return NULL;
      cur->new = 1;
      cur->conns = g_hash_table_new_full((GHashFunc)hash_connkey,
         (GEqualFunc)eq_connkey, free, free );
      cur->snipe = 0;
      g_hash_table_insert( ses->hosts, (gpointer)addr.s_addr, cur );
   }
   return cur;
}

struct conn *lookup_connection( struct host *src, struct in_addr dst,
   unsigned short sport, unsigned short dport )
{
   struct connkey key = { dst, sport, dport };

   return g_hash_table_lookup( src->conns, &key );
}

struct conn *get_connection( struct host *src, struct in_addr dst,
   unsigned short sport, unsigned short dport )
{
   struct connkey *newkey, key = { dst, sport, dport };
   struct conn *cur = g_hash_table_lookup( src->conns, &key );

   if( cur == NULL )
   {
      if(( cur = malloc( sizeof( struct conn ))) == NULL )
         return NULL;
      if(( newkey = malloc( sizeof( struct connkey ))) == NULL )
         return NULL;
      newkey->addr = dst;
      newkey->sport = sport;
      newkey->dport = dport;
      cur->new = 1;
      cur->state = ESTABLISHED;
      cur->in = 0;
      cur->out = 0;
      cur->snipe = 0;
      g_hash_table_insert( src->conns, newkey, cur );
   }
   return cur;
}

void remove_connection( struct host *src, struct in_addr dst, unsigned short sport,
   unsigned short dport )
{
   struct connkey key = { dst, sport, dport };

   g_hash_table_remove( src->conns, &key );
}

int setup_session( struct session *ses )
{
   int i, sd;
   struct ifreq inf;
   struct bpf_insn insns[] =
   {
      BPF_STMT( BPF_LD + BPF_H + BPF_ABS, 12 ),
      BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 3 ),
      BPF_STMT( BPF_LD + BPF_B + BPF_ABS, 23 ),
      BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 1 ),
      BPF_STMT( BPF_RET + BPF_K, -1 ),
      BPF_STMT( BPF_RET + BPF_K, 0 )
   };
   struct bpf_program fil = { 6, insns };

   ses->killin = 0;
   for( i = 0; i < 10; i++ )
   {
      char file[10];

      sprintf( file, "/dev/bpf%d", i );
      if(( ses->bpf = open( file, O_RDWR )) != -1 )
         break;
   }
   if( ses->bpf == -1 )
   {
      //perror( "unable to open bpf device" );
      return -1;
   }
   ses->len = BUFFER;
   if( ioctl( ses->bpf, BIOCSBLEN, &ses->len ) == -1 )
   {
      //perror( "Unable to set buffer length" );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   strncpy( inf.ifr_name, ses->if_name, IFNAMSIZ );
   if( ioctl( ses->bpf, BIOCSETIF, &inf ) == -1 )
   {
      //char tmp[32];

      //sprintf( tmp, "Unable to open %s", inf.ifr_name );
      //perror( tmp );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   if(( sd = socket( AF_INET, SOCK_DGRAM, 0 )) == -1 )
   {
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   if( ioctl( sd, SIOCGIFADDR, &inf ) == -1 )
   {
      close( sd );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   ses->if_addr = ((struct sockaddr_in *)&inf.ifr_addr )->sin_addr;
   if( ioctl( sd, SIOCGIFNETMASK, &inf ) == -1 )
   {
      close( sd );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   ses->if_mask = ((struct sockaddr_in *)&inf.ifr_addr )->sin_addr;
   ses->if_net.s_addr = ses->if_addr.s_addr & ses->if_mask.s_addr;
   close( sd );
   i = 1;   
   if( ioctl( ses->bpf, BIOCIMMEDIATE, &i ) == -1 )
   {
      //perror( "Unable to set immediate mode" );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   if( ioctl( ses->bpf, BIOCPROMISC, NULL ) == -1 )
   {
      //perror( "Unable to put the interface in promiscuous mode" );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   i = 1;
   if( ioctl( ses->bpf, BIOCSHDRCMPLT, &i ) == -1 )
   {
      //perror( "Unable to put the interface in header complete mode" );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   if( ioctl( ses->bpf, BIOCSETF, &fil ) == -1 )
   {
      //perror( "Unable to set filter" );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   if(( ses->buff = malloc( ses->len )) == NULL )
   {
      //perror( "Unable to allocate recieve buffer" );
      close( ses->bpf );
      ses->bpf = -1;
      return -1;
   }
   ses->hosts = g_hash_table_new_full( g_direct_hash, g_direct_equal, NULL,
      (GDestroyNotify)free_host );
   return 0;
}

void destroy_session( struct session *ses )
{
   close( ses->bpf );
   ses->bpf = -1;
   free( ses->buff );
   ses->buff = NULL;
   g_hash_table_destroy( ses->hosts );
   ses->hosts = NULL;
   ses->killin = 0;
}

gboolean session_io( GIOChannel *io, GIOCondition cond, struct session *ses )
{
   unsigned int r;
   struct bpf_hdr *hdr;

   if( ses->bpf == -1 )
      return FALSE;
   r = read( ses->bpf, ses->buff, ses->len );
   for( hdr = ses->buff; (char *)hdr - (char *)ses->buff < r;
      hdr = (struct bpf_hdr *)((char *)hdr + BPF_WORDALIGN( hdr->bh_hdrlen
      + hdr->bh_caplen )))
   {
      char *p = (char *)hdr + hdr->bh_hdrlen;
      char packet[66];
      struct ether_header *eth = (struct ether_header *)p;
      struct ip *iph = (struct ip *)( p + 14 );
      struct tcphdr *tcph = (struct tcphdr *)( p + 14 + iph->ip_hl * 4 );
      struct ether_header *peth = (struct ether_header *)packet;
      struct ip *pip = (struct ip *)( packet + 14 );
      struct tcphdr *ptcp = (struct tcphdr *)( packet + 34 );
      struct tcpsum *psum = (struct tcpsum *)( packet + 54 );


      if(( iph->ip_src.s_addr & ses->if_mask.s_addr ) == ses->if_net.s_addr )
      {
         struct host *src;
         struct conn *cn;

         if(( src = get_host( ses, iph->ip_src )) != NULL )
         {
            src->alive = LIFETIME;
            if(( cn = get_connection( src, iph->ip_dst, ntohs( tcph->th_sport ),
               ntohs( tcph->th_dport ))) != NULL )
            {
               cn->out += ntohs( iph->ip_len ) - iph->ip_hl * 4 - tcph->th_off
                  * 4;
               if(( src->snipe || cn->snipe ) && !( tcph->th_flags & TH_RST ))
               {
                  memcpy( peth->ether_dhost, eth->ether_shost, 6 );
                  memcpy( peth->ether_shost, eth->ether_dhost, 6 );
                  peth->ether_type = htons( ETHERTYPE_IP );
                  pip->ip_v = 4;
                  pip->ip_hl = 5;
                  pip->ip_tos = 0;
                  pip->ip_len = htons( 40 );
                  pip->ip_id = random( );
                  pip->ip_off = 0;
                  pip->ip_ttl = 64;
                  pip->ip_p = IPPROTO_TCP;
                  pip->ip_sum = 0;
                  pip->ip_src = iph->ip_dst;
                  pip->ip_dst = iph->ip_src;
                  pip->ip_sum = in_cksum( packet + 14, 20 );
                  ptcp->th_sport = tcph->th_dport;
                  ptcp->th_dport = tcph->th_sport;
                  ptcp->th_seq = tcph->th_ack;
                  if( tcph->th_flags & TH_SYN )
                     ptcp->th_ack = htonl( ntohl( tcph->th_seq ) + 1 );
                  else
                     ptcp->th_ack = htonl( ntohl( tcph->th_seq )
                        + ntohs( iph->ip_len ) - iph->ip_hl * 4 - tcph->th_off
                        * 4 );
                  ptcp->th_off = 5;
                  ptcp->th_x2 = 0;
                  ptcp->th_flags = TH_RST | TH_ACK;
                  ptcp->th_win = 0;
                  ptcp->th_sum = 0;
                  ptcp->th_urp = 0;
                  psum->ip_src = pip->ip_src;
                  psum->ip_dst = pip->ip_dst;
                  psum->zero = 0;
                  psum->ip_p = IPPROTO_TCP;
                  psum->len = htons( 20 );
                  ptcp->th_sum = in_cksum( packet + 34, 32 );
                  write( ses->bpf, packet, 54 );
               }
               if( tcph->th_flags & TH_RST )
                  remove_connection( src, iph->ip_dst, ntohs( tcph->th_sport ),
                     ntohs( tcph->th_dport ));
               else if( tcph->th_flags == TH_SYN )
               {
                  cn->state = SYN_WAIT;
                  cn->timeout = TIMEOUT;
               }
               else if( tcph->th_flags & TH_FIN )
	       {
		  if( cn->state != FIN_WAIT )
                  {
                     cn->state = FIN_WAIT;
                     cn->timeout = TIMEOUT;
		  }
               }
               else
               {
		  cn->timeout = LIFETIME;
                  if( cn->state == SYN_WAIT )
                     cn->state = ESTABLISHED;
                  else if( cn->state == FIN_WAIT && tcph->th_flags & TH_ACK )
                     remove_connection( src, iph->ip_dst,
                        ntohs( tcph->th_sport ), ntohs( tcph->th_dport ));
               }
            }
         }
      }
      if(( iph->ip_dst.s_addr & ses->if_mask.s_addr ) == ses->if_net.s_addr )
      {
         struct host *dst;
         struct conn *cn;

         if(( dst = get_host( ses, iph->ip_dst )) != NULL )
         {
            dst->alive = LIFETIME;
            if(( cn = get_connection( dst, iph->ip_src, ntohs( tcph->th_dport ),
               ntohs( tcph->th_sport ))) != NULL )
            {
               cn->in += ntohs( iph->ip_len ) - iph->ip_hl * 4 - tcph->th_off
                  * 4;
               if(( dst->snipe || cn->snipe ) && !( tcph->th_flags & TH_RST ))
               {
                  memcpy( peth->ether_dhost, eth->ether_shost, 6 );
                  memcpy( peth->ether_shost, eth->ether_dhost, 6 );
                  peth->ether_type = htons( ETHERTYPE_IP );
                  pip->ip_v = 4;
                  pip->ip_hl = 5;
                  pip->ip_tos = 0;
                  pip->ip_len = htons( 40 );
                  pip->ip_id = random( );
                  pip->ip_off = 0;
                  pip->ip_ttl = 64;
                  pip->ip_p = IPPROTO_TCP;
                  pip->ip_sum = 0;
                  pip->ip_src = iph->ip_dst;
                  pip->ip_dst = iph->ip_src;
                  pip->ip_sum = in_cksum( packet + 14, 20 );
                  ptcp->th_sport = tcph->th_dport;
                  ptcp->th_dport = tcph->th_sport;
                  ptcp->th_seq = tcph->th_ack;
                  if( tcph->th_flags & TH_SYN )
                     ptcp->th_ack = htonl( ntohl( tcph->th_seq ) + 1 );
                  else
                     ptcp->th_ack = htonl( ntohl( tcph->th_seq )
                        + ntohs( iph->ip_len ) - iph->ip_hl * 4 - tcph->th_off
                        * 4 );
                  ptcp->th_off = 5;
                  ptcp->th_x2 = 0;
                  ptcp->th_flags = TH_RST | TH_ACK;
                  ptcp->th_win = 0;
                  ptcp->th_sum = 0;
                  ptcp->th_urp = 0;
                  psum->ip_src = pip->ip_src;
                  psum->ip_dst = pip->ip_dst;
                  psum->zero = 0;
                  psum->ip_p = IPPROTO_TCP;
                  psum->len = htons( 20 );
                  ptcp->th_sum = in_cksum( packet + 34, 32 );
                  write( ses->bpf, packet, 54 );
               }
               if( tcph->th_flags & TH_RST )
                  remove_connection( dst, iph->ip_src, ntohs( tcph->th_dport ),
                     ntohs( tcph->th_sport ));
               else if( tcph->th_flags == TH_SYN )
               {
                  cn->state = SYN_WAIT;
                  cn->timeout = TIMEOUT;
               }
               else if( tcph->th_flags & TH_FIN )
	       {
		  if( cn->state != FIN_WAIT )
                  {
                     cn->state = FIN_WAIT;
                     cn->timeout = TIMEOUT;
		  }
               }
               else
               {
		  cn->timeout = LIFETIME;
                  if( cn->state == SYN_WAIT )
                     cn->state = ESTABLISHED;
                  else if( cn->state == FIN_WAIT && tcph->th_flags & TH_ACK )
                     remove_connection( dst, iph->ip_src,
                        ntohs( tcph->th_dport ), ntohs( tcph->th_sport ));
               }
            }
         }
      }
   }
   return TRUE;
}

void underpants( struct connkey *key, struct conn *cn, void *pair[] )
{
   struct session *ses = pair[0];
   struct host *hst = pair[1];
   struct connkey *newkey;
   GtkTreeIter iter;
   char info[200];

   if( cn->new )
   {
      cn->new = 0;
      if(( newkey = malloc( sizeof( struct connkey ))) == NULL )
         return;
      newkey->addr = key->addr;
      newkey->sport = key->sport;
      newkey->dport = key->dport;
      sprintf( info, "%d -> %s:%d", key->sport, inet_ntoa( key->addr ),
         key->dport );
      gtk_tree_store_append( ses->store, &iter, &hst->iter );
      gtk_tree_store_set( ses->store, &iter, 0, info, 2, "green", 3, newkey,
         -1 );
   }
}

void profit( gpointer key, struct host *hst, struct session *ses )
{
   struct in_addr addr = { (in_addr_t)key };
   void *pair[2];

   if( hst->new )
   {
      hst->new = 0;
      gtk_tree_store_append( ses->store, &hst->iter, NULL );
      gtk_tree_store_set( ses->store, &hst->iter, 0, inet_ntoa( addr ), 2,
         "green", 3, key, -1 );
   }
   pair[0] = ses;
   pair[1] = hst;
   g_hash_table_foreach( hst->conns, (GHFunc)underpants, pair );
}

gboolean session_update( struct session *ses )
{
   GtkTreeModel *model = GTK_TREE_MODEL( ses->store );
   GtkTreeIter curhost, curconn;
   gboolean valid;

   // phase 1: age colors
   for( valid = gtk_tree_model_get_iter_first( model, &curhost ); valid;
      valid = gtk_tree_model_iter_next( model, &curhost ))
   {
      char *color;

      gtk_tree_model_get( model, &curhost, 2, &color, -1 );
      if( strcmp( color, "red" ) == 0 )
      {
         for( valid = gtk_tree_model_iter_children( model, &curconn, &curhost );
            valid; valid = gtk_tree_store_remove( ses->store, &curconn ))
         {
            struct connkey *key;

            gtk_tree_model_get( model, &curconn, 3, &key, -1 );
            free( key );
         }
         if( !gtk_tree_store_remove( ses->store, &curhost ))
            break;
      }
      else
      {
         if( strcmp( color, "green" ) == 0 )
            gtk_tree_store_set( ses->store, &curhost, 2, "white", -1 );
         for( valid = gtk_tree_model_iter_children( model, &curconn, &curhost );
            valid; valid = gtk_tree_model_iter_next( model, &curconn ))
         {
            gtk_tree_model_get( model, &curconn, 2, &color, -1 );
            if( strcmp( color, "red" ) == 0 )
            {
               struct connkey *key;

               gtk_tree_model_get( model, &curconn, 3, &key, -1 );
               free( key );
               if( !gtk_tree_store_remove( ses->store, &curconn ))
                  break;
            }
            else if( strcmp( color, "green" ) == 0 )
               gtk_tree_store_set( ses->store, &curconn, 2, "white", -1 );
         }
      }
   }
   // phase 2: update info
   for( valid = gtk_tree_model_get_iter_first( model, &curhost ); valid;
      valid = gtk_tree_model_iter_next( model, &curhost ))
   {
      struct host *hst;
      struct in_addr addr;
      unsigned int in = 0, out = 0;
      char bw[256];

      gtk_tree_model_get( model, &curhost, 3, &addr.s_addr, -1 );
      if(( hst = lookup_host( ses, addr )) == NULL )
         gtk_tree_store_set( ses->store, &curhost, 2, "red", -1 );
      else
      {
         hst->alive--;
         hst->new = 0; // just in case
         if( hst->alive <= 0 )
         {
            g_hash_table_remove( ses->hosts, (gpointer)addr.s_addr );
            gtk_tree_store_set( ses->store, &curhost, 2, "red", -1 );
         }
         else
         {
            for( valid = gtk_tree_model_iter_children( model, &curconn,
               &curhost ); valid; valid = gtk_tree_model_iter_next( model,
               &curconn ))
            {
               struct conn *cn;
               struct connkey *ck;
   
               gtk_tree_model_get( model, &curconn, 3, &ck, -1 );
               if(( cn = lookup_connection( hst, ck->addr, ck->sport,
                  ck->dport )) == NULL )
                  gtk_tree_store_set( ses->store, &curconn, 2, "red", -1 );
               else
               {
                  cn->timeout--;
                  cn->new = 0; // just for fun
                  if( cn->timeout <= 0 )
                  {
                     g_hash_table_remove( hst->conns, ck );
                     gtk_tree_store_set( ses->store, &curconn, 2, "red", -1 );
                  }
                  else
                  {
                     in += cn->in;
                     out += cn->out;
                     sprintf( bw, "%.2f KBps in %.2f KBps out", cn->in / 1024.0,
                        cn->out / 1024.0 );
                     cn->in = 0;
                     cn->out = 0;
                     gtk_tree_store_set( ses->store, &curconn, 1, bw, -1 );
                  }
               }
            }
            sprintf( bw, "%.2f KBps in %.2f KBps out", in / 1024.0, out
               / 1024.0 );
            gtk_tree_store_set( ses->store, &curhost, 1, bw, -1 );
         }
      }
   }
   // phase 3: profit!
   g_hash_table_foreach( ses->hosts, (GHFunc)profit, ses );
   return TRUE;
}

gboolean main_delete_cb( GtkWidget *widget, GdkEvent *event, gpointer data )
{
   gtk_main_quit( );
   return FALSE;
}

void menu_start_cb( GtkWidget *item, struct session *ses )
{
   GtkWidget *dialog, *label, *entry;
   GIOChannel *io;

   if( ses->bpf != -1 )
      return;
   dialog = gtk_dialog_new_with_buttons( "Session Setup",
      GTK_WINDOW( gtk_widget_get_toplevel( GTK_WIDGET( item ))),
      GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, GTK_STOCK_OK,
      GTK_RESPONSE_ACCEPT, GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, NULL );
   label = gtk_label_new( "Network interface:" );
   entry = gtk_entry_new( );
   gtk_box_pack_start( GTK_BOX( GTK_DIALOG( dialog )->vbox ), label, FALSE,
      TRUE, 0 );
   gtk_box_pack_start( GTK_BOX( GTK_DIALOG( dialog )->vbox ), entry, FALSE,
      TRUE, 0 );
   gtk_widget_show_all( dialog );
   if( gtk_dialog_run( GTK_DIALOG( dialog )) == GTK_RESPONSE_ACCEPT )
   {
      GtkTreeModel *model = GTK_TREE_MODEL( ses->store );
      GtkTreeIter curhost, curconn;
      gboolean valid;

      strncpy( ses->if_name, gtk_entry_get_text( GTK_ENTRY( entry )),
         IFNAMSIZ );
      if( setup_session( ses ) == -1 )
      {
         gtk_widget_destroy( dialog );
         return;
      }
      for( valid = gtk_tree_model_get_iter_first( model, &curhost ); valid;
         valid = gtk_tree_store_remove( ses->store, &curhost ))
      {
         for( valid = gtk_tree_model_iter_children( model, &curconn, &curhost );
            valid; valid = gtk_tree_store_remove( ses->store, &curconn ))
         {
            struct connkey *key;

            gtk_tree_model_get( model, &curconn, 3, &key, -1 );
            free( key );
         }
      }
      io = g_io_channel_unix_new( ses->bpf );
      ses->ioid = g_io_add_watch( io, G_IO_IN, (GIOFunc)session_io, ses );
      ses->updateid = gtk_timeout_add( 1000, (GtkFunction)session_update, ses );
   }
   gtk_widget_destroy( dialog );
}

void menu_stop_cb( GtkWidget *item, struct session *ses )
{
   if( ses->bpf == -1 )
      return;
   gdk_window_set_cursor( item->window, NULL );
   g_source_remove( ses->ioid );
   gtk_timeout_remove( ses->updateid );
   destroy_session( ses );
}

void menu_kill_cb( GtkWidget *item, struct session *ses )
{
   if( ses->bpf == -1 )
      return;
   if( ses->killin )
   {
      ses->killin = 0;
      gdk_window_set_cursor( item->window, NULL );
   }
   else
   {
      ses->killin = 1;
      gdk_window_set_cursor( item->window, aim_cursor );
   }
}

void menu_quit_cb( GtkMenuItem *menuitem, gpointer data )
{
   gtk_main_quit( );
}

void tree_click_cb( GtkTreeView *tree, GtkTreePath *path,
   GtkTreeViewColumn *column, struct session *ses )
{
   GtkTreeModel *model = GTK_TREE_MODEL( ses->store );
   GtkTreeIter iter, iter2;
   struct host *hst;
   struct in_addr addr;
   struct conn *cn;
   struct connkey *ck;

   if( ses->killin )
   {
      gtk_tree_model_get_iter( model, &iter, path );
      if( gtk_tree_path_get_depth( path ) == 1 )
      {
         gtk_tree_model_get( model, &iter, 3, &addr, -1 );
         if(( hst = lookup_host( ses, addr )) == NULL )
            return;
         //printf( "%s\n", inet_ntoa( addr ));
         if( hst->snipe )
         {
            hst->snipe = 0;
            gtk_tree_store_set( ses->store, &iter, 2, "white", -1 );
         }
         else
         {
            hst->snipe = 1;
            gtk_tree_store_set( ses->store, &iter, 2, "light blue", -1 );
         }
      }
      else
      {
         if( !gtk_tree_model_iter_parent( model, &iter2, &iter ))
            return;
         gtk_tree_model_get( model, &iter2, 3, &addr, -1 );
         if(( hst = lookup_host( ses, addr )) == NULL )
            return;
         gtk_tree_model_get( model, &iter, 3, &ck, -1 );
         if(( cn = lookup_connection( hst, ck->addr, ck->sport, ck->dport ))
            == NULL )
            return;
         //printf( "%s:%d -> ", inet_ntoa( addr ), ck->sport );
         //printf( "%s:%d\n", inet_ntoa( ck->addr ), ck->dport );
         if( cn->snipe )
         {
            cn->snipe = 0;
            gtk_tree_store_set( ses->store, &iter, 2, "white", -1 );
         }
         else
         {
            cn->snipe = 1;
            gtk_tree_store_set( ses->store, &iter, 2, "light blue", -1 );
         }
      }
   }
}

GtkWidget *create_main( struct session *ses )
{
   GtkWidget *wmain, *vbox, *toolbar, *tree, *scrolling, *status;
   GtkCellRenderer *renderer;
   GtkTreeViewColumn *column;
   GtkTreeSelection *select;

   // create main window
   wmain = gtk_window_new( GTK_WINDOW_TOPLEVEL );
   g_signal_connect( G_OBJECT( wmain ), "delete-event", G_CALLBACK(
      main_delete_cb ), NULL );
   gtk_window_set_title( GTK_WINDOW( wmain ), "P2PDie v1.0" );
   gtk_window_set_resizable( GTK_WINDOW( wmain ), 1 );
   gtk_window_set_default_size( GTK_WINDOW( wmain ), 400, 300 );
   // create main container and start adding stuff
   vbox = gtk_vbox_new( 0, 0 );
   gtk_container_add( GTK_CONTAINER( wmain ), vbox );
   // create toolbar and add it to the main container
   toolbar = gtk_toolbar_new( );
   gtk_toolbar_set_icon_size( GTK_TOOLBAR( toolbar ),
      GTK_ICON_SIZE_MENU );
   gtk_toolbar_insert_stock( GTK_TOOLBAR( toolbar ), GTK_STOCK_EXECUTE,
      "Start session", NULL, (GtkSignalFunc)menu_start_cb, ses, 0 );
   gtk_toolbar_insert_stock( GTK_TOOLBAR( toolbar ), GTK_STOCK_STOP,
      "Stop session", NULL, (GtkSignalFunc)menu_stop_cb, ses, 1 );
   gtk_toolbar_append_item( GTK_TOOLBAR( toolbar ), "Kill", NULL, NULL,
      gtk_image_new_from_stock( GTK_STOCK_CLOSE, GTK_ICON_SIZE_MENU ),
      (GtkSignalFunc)menu_kill_cb, ses );
   gtk_box_pack_start( GTK_BOX( vbox ), toolbar, FALSE, TRUE, 0 );
   // create tree view and add it to the main container
   ses->store = gtk_tree_store_new( 4, G_TYPE_STRING, G_TYPE_STRING,
      G_TYPE_STRING, G_TYPE_INT );
   tree = gtk_tree_view_new_with_model( GTK_TREE_MODEL( ses->store ));
   g_signal_connect( G_OBJECT( tree ), "row-activated", G_CALLBACK(
      tree_click_cb ), ses );
   select = gtk_tree_view_get_selection( GTK_TREE_VIEW( tree ));
   gtk_tree_selection_set_mode( select, GTK_SELECTION_NONE );
   renderer = gtk_cell_renderer_text_new( );
   column = gtk_tree_view_column_new_with_attributes( "Host", renderer,
      "text", 0, "background", 2, NULL );
   gtk_tree_view_column_set_resizable( column, TRUE );
   gtk_tree_view_append_column( GTK_TREE_VIEW( tree ), column );
   renderer = gtk_cell_renderer_text_new( );
   column = gtk_tree_view_column_new_with_attributes( "Bandwidth", renderer,
      "text", 1, "background", 2, NULL );
   gtk_tree_view_column_set_resizable( column, TRUE );
   gtk_tree_view_append_column( GTK_TREE_VIEW( tree ), column );
   scrolling = gtk_scrolled_window_new( NULL, NULL );
   gtk_container_add( GTK_CONTAINER( scrolling ), tree );
   gtk_scrolled_window_set_policy( GTK_SCROLLED_WINDOW( scrolling ),
      GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC );
   gtk_scrolled_window_set_shadow_type( GTK_SCROLLED_WINDOW( scrolling ),
      GTK_SHADOW_ETCHED_OUT );
   gtk_box_pack_start( GTK_BOX( vbox ), scrolling, TRUE, TRUE, 0 );
   // create status bar and add it to the main container
   status = gtk_statusbar_new( );
   gtk_box_pack_start( GTK_BOX( vbox ), status, FALSE, TRUE, 0 );
   return wmain;
}

int main( int argc, char *argv[] )
{
   GtkWidget *wmain;
   GdkPixmap *source, *mask;
   GdkColor fg = { 0, 0, 0, 0 };
   GdkColor bg = { 0, 65535, 65535, 65535 };
   struct session ses;

   ses.bpf = -1;
   srandom( time( NULL ));
   gtk_init( &argc, &argv );
   source = gdk_bitmap_create_from_data( NULL, aim_bits, 16, 16 );
   mask = gdk_bitmap_create_from_data( NULL, aim_mask, 16, 16 );
   aim_cursor = gdk_cursor_new_from_pixmap( source, mask, &fg, &bg, 8, 8 );
   wmain = create_main( &ses );
   gtk_widget_show_all( wmain );
   gtk_main( );
   return 0;
}
