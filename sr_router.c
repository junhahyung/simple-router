/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_handlearp(struct sr_instance* sr,
		  uint8_t * packet/* lent */,
		  unsigned int len,
		  char* interface/* lent */);
void process_ip_packet(uint8_t * packet,unsigned char* rmac, unsigned char * dmac, uint32_t rip, uint32_t dip,char* iface);
  
void sr_handleip(struct sr_instance * sr, uint8_t *packet, unsigned int len,char* iface);

uint8_t* process_sr_packet(struct sr_packet * packet,unsigned char* rmac, unsigned char * dmac, uint32_t rip, uint32_t dip,char* iface);

void handle_arpreq(struct sr_instance* sr,struct sr_arpreq * req,char* iface);

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);  

  
  
  /* fill in code here */
  
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;
  
  /*if received packet is arp packet*/
  if(eth_hdr->ether_type == htons(ethertype_arp))
    {
      
      sr_handlearp(sr,packet,len,interface);
    }
  /*if received packet is ip packet*/
  else if(eth_hdr->ether_type == htons(ethertype_ip))
    {
      
      sr_handleip(sr,packet,len,interface);
    }
  else
    {
     
    }

}/* end sr_ForwardPacket */

/*input iface is incoming interface*/
void sr_handleip(struct sr_instance * sr, uint8_t *packet, unsigned int len,char* iface)
{
  assert(iface);
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  uint8_t * sendmac = eth_hdr->ether_shost;
  uint32_t sendip = ip_hdr->ip_src;
  uint32_t destip = ip_hdr->ip_dst;

  struct sr_if* ipointer = sr_get_interface(sr,iface);
  unsigned char * rmac = (unsigned char *)malloc(ETHER_ADDR_LEN);
  memcpy(rmac,ipointer->addr,ETHER_ADDR_LEN);
  uint32_t rip = ipointer->ip;
  
  if(ip_hdr->ip_ttl ==1)/*if tt1=1, discard packet and send icmp timeout*/
    {
      
      uint8_t * icmppacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t));
      sr_ethernet_hdr_t* icmp_e_hdr = (sr_ethernet_hdr_t *)icmppacket;
      /*-------ethernet header setting--------------------------------*/
      icmp_e_hdr->ether_type = htons(ethertype_ip); /* set ehternet type as ip*/
      memcpy(icmp_e_hdr->ether_dhost,sendmac,ETHER_ADDR_LEN); /*set dest mac  which is sendmac*/
      memcpy(icmp_e_hdr->ether_shost,rmac,ETHER_ADDR_LEN);/*set src mac*/
      /*--------------------------------------------------------------*/

      sr_ip_hdr_t * icmp_i_hdr = (sr_ip_hdr_t *)(icmppacket+sizeof(sr_ethernet_hdr_t));
      sr_ip_hdr_t * packet_ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
      /*---------------------ip header setting------------------------*/
      memcpy(icmp_i_hdr,packet_ip_hdr,sizeof(sr_ip_hdr_t));
      icmp_i_hdr->ip_p = ip_protocol_icmp;
      icmp_i_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t));
      icmp_i_hdr->ip_ttl = 64;
      icmp_i_hdr->ip_src = rip;
      icmp_i_hdr->ip_dst = sendip;
      icmp_i_hdr->ip_sum = 0;
      icmp_i_hdr->ip_sum = cksum(icmp_i_hdr,sizeof(sr_ip_hdr_t));
      /*---------------------ip header setting------------------------*/

      sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t*)(icmppacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

      /*--------------------icmp header setting----------------------*/
      icmp_hdr->icmp_type = 11;
      icmp_hdr->icmp_code = 0;
      icmp_hdr->icmp_sum = 0;
      icmp_hdr->icmp_sum = cksum(icmp_hdr,sizeof(sr_icmp_hdr_t));      
      /*--------------------icmp header setting----------------------*/

      /*---------------------send icmp-------------------------------*/
      sr_send_packet(sr,icmppacket,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t),iface);
      free(icmppacket);
      return;
    }
  
  struct sr_if* iflist = sr->if_list;
  int c=0;
  while(iflist)
    {
      if(iflist->ip==destip)
	c+=1;
      iflist = iflist->next;
    }

  /*packet to me*/
  if(c != 0)
    {
     
      /*it is not icmp echo request, discard, send port unreachable*/
      if(ip_hdr->ip_p != ip_protocol_icmp)
	{
	  /*make icmp port unreachable*/
	  uint8_t * icmppacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
	  sr_ethernet_hdr_t* icmp_e_hdr = (sr_ethernet_hdr_t *)icmppacket;
	  /*-------ethernet header setting--------------------------------*/
	  icmp_e_hdr->ether_type = htons(ethertype_ip); /* set ehternet type as ip*/
	  memcpy(icmp_e_hdr->ether_dhost,sendmac,ETHER_ADDR_LEN); /*set dest mac  which is sendmac*/
	  memcpy(icmp_e_hdr->ether_shost,rmac,ETHER_ADDR_LEN);/*set src mac*/
	  /*--------------------------------------------------------------*/
	  
	  sr_ip_hdr_t * icmp_i_hdr = (sr_ip_hdr_t *)(icmppacket+sizeof(sr_ethernet_hdr_t));	  
	  /*---------------------ip header setting------------------------*/
	  memcpy(icmp_i_hdr,ip_hdr,sizeof(sr_ip_hdr_t));
	  icmp_i_hdr->ip_p = ip_protocol_icmp;
	  icmp_i_hdr->ip_ttl = 64;
	  icmp_i_hdr->ip_src = rip;
	  icmp_i_hdr->ip_dst = sendip;
	  icmp_i_hdr->ip_sum = 0;
	  icmp_i_hdr->ip_sum = cksum(icmp_i_hdr,sizeof(sr_ip_hdr_t));
	  /*---------------------ip header setting------------------------*/
	  
	  sr_icmp_t3_hdr_t * icmp_hdr = (sr_icmp_t3_hdr_t*)(icmppacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

	  /*--------------------icmp header setting----------------------*/
	  icmp_hdr->icmp_type = 3;
	  icmp_hdr->icmp_code = 3;
	  icmp_hdr->unused = 0;
	  icmp_hdr->next_mtu = 0;
	  uint8_t data[ICMP_DATA_SIZE] = {0};
	  memcpy(icmp_hdr->data,data,ICMP_DATA_SIZE);
	  icmp_hdr->icmp_sum = 0;
	  icmp_hdr->icmp_sum = cksum(icmp_hdr,sizeof(sr_icmp_hdr_t));      
	  /*--------------------icmp header setting----------------------*/
	  
	  /*---------------------send icmp-------------------------------*/
	  sr_send_packet(sr,icmppacket,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t),iface);

	  free(icmppacket);
	  return;
	}
      /*sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));*/
   
      /*it is an icmp echo request, check cksum, send icmp echo reply*/
      else
	{
	  uint16_t n = ip_hdr->ip_sum;
	  ip_hdr->ip_sum = 0;
	  sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	  
	  if(n != cksum(ip_hdr,sizeof(sr_ip_hdr_t)))
	    {
	      printf("received ICMP echo request has invalid checksum \n");
	      return;}

	  uint8_t * newpkt = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t));
	  sr_ethernet_hdr_t * n_eth_hdr = (sr_ethernet_hdr_t *)newpkt;
	  sr_ip_hdr_t * n_ip_hdr = (sr_ip_hdr_t *)(newpkt + sizeof(sr_ethernet_hdr_t));
	  sr_icmp_hdr_t * n_icmp_hdr = (sr_icmp_hdr_t *)(newpkt + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

	  memcpy(newpkt,packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t));

	  /*-------ethernet header setting--------------------------------*/
	  memcpy(n_eth_hdr->ether_dhost,sendmac,ETHER_ADDR_LEN); /*set dest mac  which is sendmac*/
	  memcpy(n_eth_hdr->ether_shost,rmac,ETHER_ADDR_LEN);/*set src mac*/
	  /*--------------------------------------------------------------*/
	  
	  /*---------------------ip header setting------------------------*/
	  n_ip_hdr->ip_ttl = 64;
	  n_ip_hdr->ip_src = rip;
	  n_ip_hdr->ip_dst = sendip;
	  n_ip_hdr->ip_sum = 0;
	  n_ip_hdr->ip_sum = cksum(n_ip_hdr,sizeof(sr_ip_hdr_t));
	  /*---------------------ip header setting------------------------*/

	  
	  /*---------------------icmp header setting------------------------*/
	  n_icmp_hdr->icmp_type = 0;
	  n_icmp_hdr->icmp_sum = 0;
	  n_icmp_hdr->icmp_sum = cksum(n_icmp_hdr,sizeof(sr_icmp_hdr_t));
	  /*---------------------icmp header setting------------------------*/
	  
	  /*send icmp echo reply*/
	  sr_send_packet(sr,newpkt,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t),iface);
	  return;
	}/*icmp echo request*/
      return;
    }/*packet to me finish*/
  
  /*packet to somewhere else*/
  else
    {
      
      struct in_addr dest;
      dest.s_addr = (unsigned int)(ip_hdr->ip_dst);
      char* t = inet_ntoa(dest);
      char * targetdecip = (char *)malloc(strlen(t)+1);
      strncpy(targetdecip,t,strlen(t)+1);
      char* rtabledecip;
      char* temp1 = (char*)malloc(strlen(targetdecip)+1);
      strncpy(temp1,targetdecip,strlen(targetdecip)+1);
      char* temp2 = temp1;
      char* outiface = (char*)malloc(sr_IFACE_NAMELEN);
      int n = 0;
      int nomatch=1;
      while(n<3)
	{
	  if(*temp2=='.')
	    n+=1;
	  temp2++;
	}
      struct sr_rt * table = sr->routing_table;
      while(table)
	{
	  rtabledecip = inet_ntoa(table->dest);
	  
	  
	  if(strncmp(rtabledecip,targetdecip,temp2-temp1+1)==0)
	    {
	      strncpy(outiface,table->interface,sr_IFACE_NAMELEN);
	      
	      nomatch=0;
	    }
	  table=table->next;
	}
      if(nomatch==1)/*there is no matching dest-->net unreachable*/
	{
	  
	  /*make icmp net unreachable*/
	  uint8_t * icmppacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
	  sr_ethernet_hdr_t* icmp_e_hdr = (sr_ethernet_hdr_t *)icmppacket;
	  /*-------ethernet header setting--------------------------------*/
	  icmp_e_hdr->ether_type = htons(ethertype_ip); /* set ehternet type as ip*/
	  memcpy(icmp_e_hdr->ether_dhost,sendmac,ETHER_ADDR_LEN); /*set dest mac  which is sendmac*/
	  memcpy(icmp_e_hdr->ether_shost,rmac,ETHER_ADDR_LEN);/*set src mac*/
	  /*--------------------------------------------------------------*/
	  
	  sr_ip_hdr_t * icmp_i_hdr = (sr_ip_hdr_t *)(icmppacket+sizeof(sr_ethernet_hdr_t));	  
	  /*---------------------ip header setting------------------------*/
	  memcpy(icmp_i_hdr,ip_hdr,sizeof(sr_ip_hdr_t));
	  icmp_i_hdr->ip_p = ip_protocol_icmp;
	  icmp_i_hdr->ip_ttl = 64;
	  icmp_i_hdr->ip_src = rip;
	  icmp_i_hdr->ip_dst = sendip;
	  icmp_i_hdr->ip_sum = 0;
	  icmp_i_hdr->ip_sum = cksum(icmp_i_hdr,sizeof(sr_ip_hdr_t));
	  /*---------------------ip header setting------------------------*/
	  
	  sr_icmp_t3_hdr_t * icmp_hdr = (sr_icmp_t3_hdr_t*)(icmppacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	  
	  /*--------------------icmp header setting----------------------*/
	  icmp_hdr->icmp_type = 3;
	  icmp_hdr->icmp_code = 0;
	  icmp_hdr->unused = 0;
	  icmp_hdr->next_mtu = 0;
	  uint8_t data[ICMP_DATA_SIZE] = {0};
	  memcpy(icmp_hdr->data,data,ICMP_DATA_SIZE);
	  icmp_hdr->icmp_sum = 0;
	  icmp_hdr->icmp_sum = cksum(icmp_hdr,sizeof(sr_icmp_hdr_t));      
	  /*--------------------icmp header setting----------------------*/
	  
	  /*---------------------send icmp-------------------------------*/
	  sr_send_packet(sr,icmppacket,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t),iface);

	  free(targetdecip);
	  free(outiface);
	  free(temp1);
       	  free(icmppacket);
	  return;	  
	}/*nomatch*/
      
      
      assert(outiface);
      struct sr_if* outifp = sr_get_interface(sr,outiface);
      unsigned char *outmac = outifp->addr;
      
      /*arp cache lookup*/
      struct sr_arpcache *cache = &(sr->cache);
      struct sr_arpentry* entry = sr_arpcache_lookup(cache,ip_hdr->ip_dst);
      if(entry)/*mac exist in cache*/
	{
	  process_ip_packet(packet,outmac,entry->mac,entry->ip,ip_hdr->ip_dst,outiface);
	  sr_send_packet(sr,packet,len,outiface);
	  
	}
      else/*should send arp request, have to put in queue*/
	{
	  /*assert(outiface);*/
	  struct sr_arpreq * req = sr_arpcache_queuereq(cache,ip_hdr->ip_dst,packet,len,outiface);
	  
	  /*assert(outiface);*/
	  /*printf("outiface just before arpreq() : %s\n",outiface);*/
	  handle_arpreq(sr,req,outiface);
	  
	  
	}
      free(targetdecip);
      free(outiface);
      free(temp1);
      free(entry);
    }/*to somewhere else*/

  free(rmac);
  return;
}/*end of handleip*/

void handle_arpreq(struct sr_instance* sr,struct sr_arpreq * req,char* iface)
{
  /*assert(iface);*/
  /*printf("iface : %s\n",iface);*/
  struct sr_if* ipointer = sr->if_list;
  time_t now;
  time(&now);
  if(difftime(now,req->sent)>1.0)
    {
      if(req->times_sent >= 5)
	{
	  struct sr_packet* packet = req->packets;
	  /*send icmp host unreachable to all pkts*/
	  while(packet)
	    {
	      uint8_t *buf = packet->buf; 
	      sr_ethernet_hdr_t* peth_hdr = (sr_ethernet_hdr_t *)buf;
	      uint8_t *peth_dst = peth_hdr->ether_dhost;
	      uint8_t *peth_src = peth_hdr->ether_shost;
	      sr_ip_hdr_t * pip_hdr = (sr_ip_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t));
	      /*uint32_t pip_dst = pip_hdr->ip_dst;*/
	      
	      while(ipointer)
		{
		  if(strncmp((const char*)ipointer->addr,(const char*)peth_dst,ETHER_ADDR_LEN)==0)
		    break;
		  ipointer = ipointer->next;
		}
	      char * reciface = ipointer->name;
	      
	      /*make icmp host unreachable*/
	      uint8_t * icmppacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
	      sr_ethernet_hdr_t* icmp_e_hdr = (sr_ethernet_hdr_t *)icmppacket;
	      /*-------ethernet header setting--------------------------------*/
	      icmp_e_hdr->ether_type = htons(ethertype_ip); /* set ehternet type as ip*/
	      memcpy(icmp_e_hdr->ether_dhost,peth_src,ETHER_ADDR_LEN); /*set dest mac  which is sendmac*/
	      memcpy(icmp_e_hdr->ether_shost,peth_dst,ETHER_ADDR_LEN);/*set src mac*/
	      /*--------------------------------------------------------------*/
	      
	      sr_ip_hdr_t * icmp_i_hdr = (sr_ip_hdr_t *)(icmppacket+sizeof(sr_ethernet_hdr_t));	  
	      /*---------------------ip header setting------------------------*/
	      memcpy(icmp_i_hdr,pip_hdr,sizeof(sr_ip_hdr_t));
	      icmp_i_hdr->ip_p = ip_protocol_icmp;
	      icmp_i_hdr->ip_ttl = 64;
	      icmp_i_hdr->ip_src = ipointer->ip;
	      icmp_i_hdr->ip_dst = pip_hdr->ip_src;
	      icmp_i_hdr->ip_sum = 0;
	      icmp_i_hdr->ip_sum = cksum(icmp_i_hdr,sizeof(sr_ip_hdr_t));
	      /*---------------------ip header setting------------------------*/
	      
	      sr_icmp_t3_hdr_t * icmp_hdr = (sr_icmp_t3_hdr_t*)(icmppacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	      
	      /*--------------------icmp header setting----------------------*/
	      icmp_hdr->icmp_type = 3;
	      icmp_hdr->icmp_code = 1;
	      icmp_hdr->unused = 0;
	      icmp_hdr->next_mtu = 0;
	      uint8_t data[ICMP_DATA_SIZE] = {0};
	      memcpy(icmp_hdr->data,data,ICMP_DATA_SIZE);
	      icmp_hdr->icmp_sum = 0;
	      icmp_hdr->icmp_sum = cksum(icmp_hdr,sizeof(sr_icmp_hdr_t));      
	      /*--------------------icmp header setting----------------------*/
	  
	      /*---------------------send icmp-------------------------------*/
	      sr_send_packet(sr,icmppacket,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t),reciface);

	      free(icmppacket);
	      
	      packet=packet->next;
	    }/*while packet*/
	  return;
	}
      
      else/*send arp request*/
	{
	  uint32_t tip = req->ip; /* target ip*/
	  ipointer = sr_get_interface(sr, iface);
	  unsigned char * rmac = ipointer->addr;
	  uint32_t rip = ipointer->ip;
	  
	  /*make arp request packet*/
	  uint8_t * arpreq = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
	  sr_ethernet_hdr_t* arp_e_hdr = (sr_ethernet_hdr_t *)arpreq;
	  /*-------ethernet header setting--------------------------------*/
	  arp_e_hdr->ether_type = htons(ethertype_arp); /* set ehternet type as arp*/
	  memcpy(arp_e_hdr->ether_shost,rmac,ETHER_ADDR_LEN); /*set dest mac  which is rmac*/
	  arp_e_hdr->ether_dhost[0]=0xff;
	  arp_e_hdr->ether_dhost[1]=0xff;
	  arp_e_hdr->ether_dhost[2]=0xff;
	  arp_e_hdr->ether_dhost[3]=0xff;
	  arp_e_hdr->ether_dhost[4]=0xff;
	  arp_e_hdr->ether_dhost[5]=0xff;
	  /*--------------------------------------------------------------*/

	  sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t*)(arpreq+sizeof(sr_ethernet_hdr_t)); 
	  /*-------------------arp header setting-------------------------*/
	  arp_hdr->ar_hrd = htons(1);
	  arp_hdr->ar_pro=htons(2048);
	  arp_hdr->ar_hln=6;
	  arp_hdr->ar_pln =4;
	  arp_hdr->ar_op = htons(arp_op_request);
	  memcpy(arp_hdr->ar_sha,rmac,ETHER_ADDR_LEN);
	  arp_hdr->ar_tha[0]=0;
	  arp_hdr->ar_tha[1]=0;
	  arp_hdr->ar_tha[2]=0;
	  arp_hdr->ar_tha[3]=0;
	  arp_hdr->ar_tha[4]=0;
	  arp_hdr->ar_tha[5]=0;
	  arp_hdr->ar_sip = rip;
	  arp_hdr->ar_tip = tip;
	  /*-------------------arp header setting-------------------------*/

	  /*print*/
	  

	  sr_send_packet(sr,arpreq,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t),iface);
	  req->sent = now;
	  req->times_sent++;
	  free(arpreq);

	  return;
	  
	}/*else*/
    }
				
  return;
}

/*rip and dip should be network byte order*/
uint8_t * process_sr_packet(struct sr_packet * packet,unsigned char* rmac, unsigned char * dmac, uint32_t rip, uint32_t dip,char* iface)
{
  unsigned int len = packet->len;
  uint8_t * buf = (uint8_t *)malloc(len);
  memcpy(buf,packet->buf,len);
  memcpy(((sr_ethernet_hdr_t *)buf)->ether_dhost,dmac,ETHER_ADDR_LEN);
  memcpy(((sr_ethernet_hdr_t *)buf)->ether_shost,rmac,ETHER_ADDR_LEN);
  /*((sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t)))->ip_src=rip;*/
    /*((sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t)))->ip_dst=dip;*/
  memcpy(packet->iface,iface,sr_IFACE_NAMELEN);

  /*ttl -1*/
  (((sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t)))->ip_ttl)--;

  /*checksum*/
  ((sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t)))->ip_sum=0;
  ((sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t)))->ip_sum=cksum(buf+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t)); 

  return buf;
  
}/*process_sr_packet*/

void process_ip_packet(uint8_t * packet,unsigned char* rmac, unsigned char * dmac, uint32_t rip, uint32_t dip,char* iface)
{
  memcpy(((sr_ethernet_hdr_t *)packet)->ether_dhost,dmac,ETHER_ADDR_LEN);
  memcpy(((sr_ethernet_hdr_t *)packet)->ether_shost,rmac,ETHER_ADDR_LEN);
  /*((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_src=rip;
    ((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_dst=dip;*/
  
  /*ttl -1*/
  (((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_ttl)--;

  /*checksum*/
  ((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_sum=0;
  ((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_sum=cksum(packet+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t)); 

  
}/*process_ip_packet*/


void sr_handlearp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(interface);
  
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_arpcache* cache = &(sr->cache);
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;
  struct sr_if * ipointer = sr_get_interface(sr,interface);
  sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));

  uint8_t * newpkt = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
  
  /* check if it is an arp reply or arp request */
  
  if(ntohs(arp_hdr->ar_op)==arp_op_request)/*received arp is arp request*/
    {/*start from here make arpreply packet*/

      memcpy(newpkt,packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t * n_eth_hdr = (sr_ethernet_hdr_t *)newpkt;
      sr_arp_hdr_t * n_arp_hdr = (sr_arp_hdr_t *)(newpkt + sizeof(sr_ethernet_hdr_t));
      memcpy(n_eth_hdr->ether_dhost,eth_hdr->ether_shost,ETHER_ADDR_LEN);
      memcpy(n_eth_hdr->ether_shost,ipointer->addr,ETHER_ADDR_LEN);
      memcpy(n_arp_hdr->ar_tha,eth_hdr->ether_shost,ETHER_ADDR_LEN);      
      memcpy(n_arp_hdr->ar_sha,ipointer->addr,ETHER_ADDR_LEN);      
      n_arp_hdr->ar_tip=arp_hdr->ar_sip;
      n_arp_hdr->ar_sip=arp_hdr->ar_tip;
      n_arp_hdr->ar_op = htons(arp_op_reply);

      /*send packet*/
      sr_send_packet(sr,newpkt,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t),interface);

     
      
    }/*received arp is arp request*/

  else if(ntohs(arp_hdr->ar_op)==arp_op_reply)/*received arp is arp reply*/
    {
      unsigned char *mac = arp_hdr->ar_sha; 
      unsigned char *rmac = arp_hdr->ar_tha; 
      uint32_t ip = arp_hdr->ar_sip; /* NBO */
      uint32_t rip = ipointer->ip; /* NBO */      
      struct sr_arpreq *req = sr_arpcache_insert(cache,mac,ip);/*cache mac->ip entry*/
      if(req)/*request was in the queue, send all waiting packets, destroy*/
	{
	  struct sr_packet * packets = req->packets;
	  while(packets)
	    {	      
	      /*modify packet*/
	      uint8_t * spacket; 
	      spacket = process_sr_packet(packets,rmac,mac,rip,ip,interface);	      
	      sr_send_packet(sr,spacket,packets->len,packets->iface);
	      
	      packets = packets->next;
	      free(spacket);
	    }
	  sr_arpreq_destroy(cache,req);	  
	}
      
    }/*received arp is arp reply*/

  else
    {
      printf("weird packet! wrong arp_op.. neither arp request or reply");
      return ;
    }
  free(newpkt);
  
  
  
}
