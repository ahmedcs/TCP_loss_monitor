/*
 * lossprobe - Observe the TCP flow with jprobes.
 *
 *  Author: Ahmed Mohamed Abdelmoniem Sayed, <ahmedcs982@gmail.com, github:ahmedcs>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of CRAPL LICENCE avaliable at
 *    http://matt.might.net/articles/crapl/.
 *    http://matt.might.net/articles/crapl/CRAPL-LICENSE.txt
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the CRAPL LICENSE for more details.
 *
 * Please READ carefully the attached README and LICENCE file with this software
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/random.h>
#include <net/net_namespace.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <net/tcp.h>
#include <linux/jhash.h>

MODULE_AUTHOR("Ahmed Sayed <ahmedcs982@gmail.com");
MODULE_DESCRIPTION("TCP loss events tracker");
MODULE_LICENSE("CRAPL");
MODULE_VERSION("1.0");

static int port __read_mostly = 0;
MODULE_PARM_DESC(port, "Port to match (0=all)");
module_param(port, int, 0);

static unsigned int bufsize __read_mostly = 4096;
MODULE_PARM_DESC(bufsize, "Log buffer size in packets (4096)");
module_param(bufsize, uint, 0);

static const char procname1[] = "lossprobe1";
static const char procname2[] = "lossprobe2";
static const char procname3[] = "lossprobe3";

static u32 hash_seed;
static u32 flow[4];

#define SIZE ((1<<18)-1) //32768 //16384 //(1>>14)
#define MAX_INT ((1<<32)-1)

#define OPEN_TOS 240
#define CLOSE_TOS 248

#define OUR_TTL 127
#define MIN_TIMEOUT 200000
//int lossprobe_init(void);
//void lossprobe_exit(void);

static inline int hash(const struct inet_sock *inet, const struct inet_request_sock *ireq)
{
     u32 temp_hash, temp_hash1, temp_hash2;
     if(ireq)
     {
        flow[0] = (u32) ireq->ir_loc_addr;
        flow[1] = (u32) ireq->ir_rmt_addr;
        flow[2] = (u32) inet->inet_sport;
        flow[3] =  (u32) ireq->ir_rmt_port;
    }
    else
    {
        flow[0] = (u32) inet->inet_saddr;
        flow[1] = (u32) inet->inet_daddr;
        flow[2] = (u32) inet->inet_sport;
        flow[3] =  (u32) inet->inet_dport;
    }

    temp_hash = jhash2(flow, 4, 0); //hash_seed);
    u32 hashval =  jhash_1word(temp_hash, hash_seed); //jhash_2words(temp_hash1, temp_hash2, hash_seed);
    int index = hashval & (SIZE-1);

    if(index>=SIZE || index<0)
    {
        if(ireq)
            pr_info("INFO: %pI4 %d %pI4 %d, Log entry hash %u %u index %d\n", &ireq->ir_loc_addr, ntohs(inet->inet_sport), &ireq->ir_rmt_addr, ntohs(ireq->ir_rmt_port), temp_hash, hashval, index);
        else
            pr_info("INFO: %pI4 %d %pI4 %d, Log entry hash %u %u index %d\n", &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), temp_hash, hashval, index);

    }
    else
         return index;
}

struct tcp_log
{
    int index;

    ktime_t tstamp;
    struct timespec tspec;
    __be32 sip,dip;
    __be16 sport,dport;
    u16	length, pkt_count, cur_mss;
    u32	snd_nxt, rcv_nxt;
    u32	snd_una;
    u32	snd_wnd;
    u32	rcv_wnd;
    u32	snd_cwnd;
    u32	ssthresh;
    unsigned int  flight_pkts;
    u32	srtt;
    //---------------------Ahmed----------------
    u32     rttvar_us;      //----- smoothed mdev_max
    u32 lost_out; //---- Lost packets
    u32 prr_out; // --- Total number of pkts sent during Recovery
    u32 prr_delivered; //--Number of packets delivered during recovery

    u32     prior_cwnd;     //-- Congestion window at start of Recovery.
    u32 prior_ssthresh; //--- ssthresh saved at recovery start
    u32 total_retrans; //--- Total retransmits for entire connection
    int     undo_retrans;   //---- number of undoable retransmissions.

    u32 retransmit_high, retransmit_ahigh; //--- high Sequence number of retransmitted data
    u32 lost_retrans_low; //---low seq Number of retransmitted data

    u32 packets_out; //-----Number of segments currently in flight
    u32 retrans_out; //----Number of packets retransmitted

    int     rcv_tstamp;     // ---- timestamp of last received ACK (for keepalives)
    int     lsndtime;       // ---- timestamp of last sent data packet (for restart window)
    int     retrans_stamp;  // ---- Timestamp of the last retransmit
    int     recovperiod;    // ----  duration of total recovery period
    int     maxrecovperiod; //  ----- maxmial recovery time experienced
    u32    init_seq, init_ack, ack_seq, pkt_seq, pkt_aseq, ack_aseq;
    __u32   retranstime;
    /*ktime_t open_time;
    ktime_t close_time;*/

    int    type, ptype;


};

static struct tcp_log logarr[SIZE];

static struct
{
    spinlock_t	lock;
    wait_queue_head_t wait;
    ktime_t		start;
    u32		lastcwnd;
    u32   last_lostout;

    unsigned long	head, tail;
    struct tcp_log	*log;
} tcp_probe1;


static struct
{
    spinlock_t	lock;
    wait_queue_head_t wait;
    ktime_t		start;
    u32		lastcwnd;
    u32   last_lostout;

    unsigned long	head, tail;
    struct tcp_log	*log;
} tcp_probe2;

static struct
{
    spinlock_t	lock;
    wait_queue_head_t wait;
    ktime_t		start;
    u32		lastcwnd;
    u32   last_lostout;

    unsigned long	head, tail;
    struct tcp_log	*log;
} tcp_probe3;

static inline int tcp_probe_used1(void)
{
    return (tcp_probe1.head - tcp_probe1.tail) & (bufsize - 1);
}

static inline int tcp_probe_used2(void)
{
    return (tcp_probe2.head - tcp_probe2.tail) & (bufsize - 1);
}

static inline int tcp_probe_used3(void)
{
    return (tcp_probe3.head - tcp_probe3.tail) & (bufsize - 1);
}

static inline int tcp_probe_avail1(void)
{
    return bufsize - tcp_probe_used1() - 1;
}

static inline int tcp_probe_avail2(void)
{
    return bufsize - tcp_probe_used2() - 1;
}

static inline int tcp_probe_avail3(void)
{
    return bufsize - tcp_probe_used3() - 1;
}

void  reset_log(struct tcp_log *p)
{
    p->index=-1;
    p->tstamp = ktime_get();
    p->sip= 0;
    p->sport = 0;
    p->dip=0;
    p->dport=0;
    p->length = p->pkt_count = p->cur_mss =0;
    p->pkt_seq = p->pkt_aseq = p->ack_seq = p->ack_aseq = p->init_seq = p->init_ack = 0;
    p->retransmit_high = p->retransmit_ahigh =0;
    p->snd_nxt =p->snd_una = p->snd_cwnd =p->snd_wnd = p->rcv_wnd = p->ssthresh = p->flight_pkts =0;
    p->lsndtime = p->rcv_tstamp = p->retrans_stamp = p->recovperiod = p->maxrecovperiod = p->retranstime = 0;

    p->srtt =  p->rttvar_us = 0;
    p->packets_out =  p->retrans_out =  p->lost_out =  p->prr_out =  p->prr_delivered = p->total_retrans = p->undo_retrans = 0;
    p->prior_ssthresh = p->prior_cwnd = 0;
}

bool fill_log(struct tcp_log *p, struct sock * sk, struct sk_buff * skb, int type)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct inet_sock *inet = inet_sk(sk);
    u32 new_seq, seq, ack;
    struct tcphdr* th;
    struct iphdr* ip;

    //int mss = tcp_current_mss(sk);
    p->tstamp = ktime_get();
    getnstimeofday(&p->tspec);

    p->sip= inet->inet_saddr;
    p->sport = inet->inet_sport;
    p->dip=inet->inet_daddr;
    p->dport=inet->inet_dport;


    if(skb)
    {
        p->length = skb->len;
        seq = p->pkt_aseq =  TCP_SKB_CB(skb)->seq; //(th && type > 2) ? th->seq :
        ack = p->ack_aseq =  TCP_SKB_CB(skb)->ack_seq; //(th && type > 2) ? th->ack_seq :
        p->pkt_count = 0;

        if(type==1)
        {
            if((signed) ( ack - p->init_seq) >= 0)
                  p->ack_seq = ack - p->init_seq;
            else
                  p->ack_seq = MAX_INT - (ack - p->init_seq) ;
            //p->pkt_seq = TCP_SKB_CB(skb)->ack_seq - p->init_ack;
            if((signed) (seq - p->init_ack) >= 0)
                  p->pkt_seq = seq - p->init_ack;
            else
                  p->pkt_seq = MAX_INT - (seq - p->init_ack) ;
            //p->ack_seq = TCP_SKB_CB(skb)->seq - p->init_seq;
        }
        else
        {
            p->pkt_count=tcp_skb_pcount(skb);
            if( (signed) seq - p->init_seq >= 0)
                p->pkt_seq = seq - p->init_seq;
            else
                p->pkt_seq = MAX_INT - seq - p->init_seq;
            p->ack_seq = 0;
            if(ack)
            {
                if((signed) (ack - p->init_ack) >= 0)
                      p->ack_seq = ack - p->init_ack;
                else
                      p->ack_seq = MAX_INT - (ack - p->init_ack);
            }
        }

    }
    else
    {
        p->length = 0;
        p->pkt_count=0;
        p->pkt_seq = 0;
        p->ack_seq = 0;
    }

    if(tp->retransmit_high)
    {
        p->retransmit_ahigh = tp->retransmit_high;
        if((signed) (tp->retransmit_high - p->init_seq) >= 0)
              p->retransmit_high = tp->retransmit_high - p->init_seq;
        else
             p->retransmit_high = MAX_INT - (tp->retransmit_high - p->init_seq) ;
        p->retranstime = (__u32)(jiffies);
    }
    else if(p->retranstime  > 0)
    {
         p->recovperiod = jiffies_to_usecs ((s32) ( (__u32)(jiffies) -  p->retranstime));
         if(!p->maxrecovperiod)
            p->maxrecovperiod = p->recovperiod;
         else if(p->recovperiod >  p->maxrecovperiod)
            p->maxrecovperiod = p->recovperiod;
          p->retranstime = 0;
    }

    if((signed) (tp->snd_nxt - p->init_seq) >= 0)
       p->snd_nxt= tp->snd_nxt - p->init_seq;
    else
       p->snd_nxt = MAX_INT - (tp->snd_nxt - p->init_seq) ;

    if((signed) (tp->snd_una - p->init_seq) >= 0)
       p->snd_una= tp->snd_una - p->init_seq;
    else
       p->snd_una = MAX_INT - (tp->snd_una - p->init_seq) ;

    if(tp->rcv_nxt)
    {
        if((signed) (tp->rcv_nxt - p->init_ack) >= 0)
           p->rcv_nxt = tp->rcv_nxt  - p->init_ack;
        else
           p->rcv_nxt  = MAX_INT - (tp->rcv_nxt  - p->init_ack) ;
    }
    else
         p->rcv_nxt=0;

    p->snd_cwnd = tp->snd_cwnd;
    p->flight_pkts = tcp_packets_in_flight(tp);
    p->snd_wnd = tp->snd_wnd;
    p->rcv_wnd = tp->rcv_wnd;
    p->ssthresh = tcp_current_ssthresh(sk);
    p->srtt = tp->srtt_us >> 3;
    //--------Ahmed--------------
    p->rttvar_us = jiffies_to_msecs (usecs_to_jiffies((tp->srtt_us >> 3) + tp->rttvar_us)); //RTO
    //p->data_segs_out = tp->data_segs_out;
    p->packets_out = tp->packets_out;
    p->retrans_out = tp->retrans_out;

    p->lost_out = tp->lost_out;
    p->prr_out = tp->prr_out;
    p->prr_delivered = tp->prr_delivered;
    p->total_retrans = tp->total_retrans;
    p->undo_retrans = tp->undo_retrans;

    //p->lost_retrans_low = tp->lost_retrans_low;
    p->cur_mss = tp->mss_cache;
    p->prior_ssthresh = tp->prior_ssthresh;
    p->prior_cwnd = tp->prior_cwnd;

    if(tp->retrans_stamp)
    	p->retrans_stamp = jiffies_to_usecs ((s32) ( (__u32)(jiffies) - tp->retrans_stamp ));
    else
	    p->retrans_stamp = 0;

    if(tp->rcv_tstamp)
        p->rcv_tstamp = jiffies_to_usecs((s32) ((__u32)(jiffies) - tp->rcv_tstamp));
    if(tp->lsndtime)
         p->lsndtime = jiffies_to_usecs((s32)( (__u32)(jiffies) - tp->lsndtime ));


	 return true;
}

void jtcp_set_state(struct sock *sk, int state)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct inet_sock *inet = inet_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);

    if(!sk || !tp || !inet || !icsk)
        goto out;

    int oldstate = sk->sk_state;

   if (state == TCP_ESTABLISHED && (oldstate !=  TCP_SYN_SENT && oldstate!= TCP_SYN_RECV))
               goto out;
   else if (state == TCP_CLOSE &&  (oldstate != TCP_LAST_ACK && oldstate != TCP_FIN_WAIT2)) //&&  oldstate != TCP_TIME_WAIT
                goto out;

    if ( (port == 0 ||  ntohs(inet->inet_dport) == port ||  ntohs(inet->inet_sport) == port))
    {
        unsigned int k = hash(inet, NULL);
        if(k>=SIZE || k<0)
            goto out;

         struct tcp_log *p = &logarr[k];


         if(state == TCP_ESTABLISHED)
         {
            if(p->index!=-1)
            {
               if(tp->lsndtime>10000 || ( p->sip==inet->inet_saddr && p->sport == inet->inet_sport &&  p->dip==inet->inet_daddr &&  p->dport==inet->inet_dport))
                    reset_log(p);
               else
               {
                    pr_info("ERROR: index:%d:%d [%pI4:%d->%pI4:%d] Init seq %#x old:%#x new:%#x\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq, oldstate, state );
                    goto out;
                }
            }
            p->index = k;
            p->init_seq = tp->snd_nxt;
            p->init_ack = tp->rcv_nxt;
            //pr_info("OPEN index:%d:%d [%pI4:%d->%pI4:%d] Init seq %#x old:%#x new:%#x\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq, oldstate, state  );

         }
         else if(state == TCP_CLOSE && p->index==-1)
            goto out;

         fill_log(p, tp, NULL, 0);

         //-------------------Note It was written originally to tcp_probe3 with retransmission events------------
         spin_lock(&tcp_probe1.lock);
        /* If log fills, just silently drop */

        if (tcp_probe_avail1() > 1)
        {
            //pr_info("TCP retransmit %pISpc -> %pISpc has been called \n", &p->src, &p->dst);
            struct tcp_log *pp = tcp_probe1.log + tcp_probe1.head;

            p->ptype = p->type;
            if(state == TCP_ESTABLISHED)
                 p->type = 4;             //Type 4 for Connection Open (go to ESTABLISHED)
            else if(state == TCP_CLOSE)
                 p->type = 5;             //Type 4 for Connection CLOSE (go to CLOSE)

            *pp = *p;

            tcp_probe1.head = (tcp_probe1.head + 1) & (bufsize - 1);
        }
        spin_unlock(&tcp_probe1.lock);

        if(state == TCP_CLOSE)
        {
              //pr_info("CLOSE index:%d:%d [%pI4:%d->%pI4:%d] Init seq %#x old:%#x new:%#x\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq, oldstate, state );
              reset_log(p);
        }

        wake_up(&tcp_probe1.wait);
    }
out:
    jprobe_return();
}
/*
 * Hook inserted to be called when jtcp_v4_do_rcv at each TCP packet arrival.
 * Note: arguments must match jtcp_v4_do_rcv()!
 */

static void jtcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct inet_sock *inet = inet_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcphdr* th;
    struct iphdr* ip;
    bool open = false, close = false, dupack=false;

     if(skb)
        th = tcp_hdr(skb);

    // ---- Only update if port or skb mark matches
    if (skb && (port == 0 ||  ntohs(th->dest) == port || ntohs(th->source) == port))
        //pr_info("RCVSKB [%pI4:%d->%pI4:%d] len:%d seq:%u:%u flags:%#x\n", &ip_hdr(skb)->saddr, ntohs(th->source), &ip_hdr(skb)->daddr, ntohs(th->dest), skb->len, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->ack_seq, TCP_SKB_CB(skb)->tcp_flags  );


        int k=hash(inet, NULL);
        if(k>=SIZE || k<0)
            goto out;
        struct tcp_log *p = &logarr[k];

        if(ntohs(ip_hdr(skb)->tos) == OPEN_TOS)
        {
            if(p->index!=-1)
                 reset_log(p);
            p->index = k;
            p->init_seq = TCP_SKB_CB(skb)->ack_seq;
            p->init_ack = TCP_SKB_CB(skb)->seq;
            open = true;
            pr_info("OPENTOS index:%d:%d [%pI4:%d->%pI4:%d] Init seq %#x flags:%#x TOS:%#x\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq, TCP_SKB_CB(skb)->tcp_flags, ntohs(ip_hdr(skb)->tos)  );

        }
        else if(ntohs(ip_hdr(skb)->tos) == CLOSE_TOS)
        {
              close = true;
              pr_info("CLOSETOS index:%d:%d [%pI4:%d->%pI4:%d] Init seq %#x flags:%#x TOS:%#x\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq, TCP_SKB_CB(skb)->tcp_flags, ntohs(ip_hdr(skb)->tos)  );
        }


        if(p->index == -1 || (!open && !close && skb->len>80))
        {
            //pr_info("OPPS:CLOSED index:%d:%d [%pI4:%d->%pI4:%d] len:%d seq:%u:%u flags:%#x\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), skb->len, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->ack_seq, TCP_SKB_CB(skb)->tcp_flags  );
            goto out;
        }

        if(TCP_SKB_CB(skb)->ack_seq==tp->snd_wnd) //p->ptype==8 || p->ptype==10) &&
            dupack=true;

        fill_log(p, tp , skb, 1);

        if(ntohs(ip_hdr(skb)->ttl) == OUR_TTL)
            pr_info("RACK index:%d:%d [%pI4:%d->%pI4:%d] Init seq %#x flags:%#x TTL:%#x\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq, TCP_SKB_CB(skb)->tcp_flags, ntohs(ip_hdr(skb)->ttl)  );

        spin_lock(&tcp_probe2.lock);

        if (tcp_probe_avail2() > 1)
        {
            struct tcp_log *pp = tcp_probe2.log + tcp_probe2.head;

            p->ptype = p->type;

             if(th->ack && skb->len<=80)
             {
                    p->type = 7; //Recieve ACK
                    if(ntohs(ip_hdr(skb)->ttl) == OUR_TTL)
                        p->type = 8;
                    else if(dupack)
                        p->type=9;
             }
             if(open)
                p->type = 10;
             else if(close)
                p->type = 11;

             *pp = *p;

            pp->sip= inet->inet_daddr;
            pp->sport = inet->inet_dport;
            pp->dip=inet->inet_saddr;
            pp->dport=inet->inet_sport;


            tcp_probe2.head = (tcp_probe2.head + 1) & (bufsize - 1);
        }

        if(close)
              reset_log(p);
        spin_unlock(&tcp_probe2.lock);

         wake_up(&tcp_probe2.wait);

    }
out:
    jprobe_return();
}

int jtcp_retransmit_skb(struct sock * sk, struct sk_buff * skb)
{

    const struct tcp_sock *tp = tcp_sk(sk);
    const struct inet_sock *inet = inet_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);

    /* Only update if port or skb mark matches */
    if (skb && ( port == 0 ||  ntohs(inet->inet_dport) == port ||  ntohs(inet->inet_sport) == port))  //tp->snd_cwnd != tcp_probe.lastcwnd)) {
    {

        int k=hash(inet, NULL);
        if(k>=SIZE || k<0)
            goto out;
        struct tcp_log *p = &logarr[k];

       if(p->index==-1 ||  p->ptype == 1 || p->type==12 || p->type==13)
            goto out;

       fill_log(p, tp, skb, 0);

        spin_lock(&tcp_probe3.lock);
        //----- If log fills, just silently drop

        if (tcp_probe_avail3() > 1)
        {
            //pr_info("TCP retransmit %pISpc -> %pISpc has been called \n", &p->src, &p->dst);
            struct tcp_log *pp = tcp_probe3.log + tcp_probe3.head;
            p->ptype = p->type;
            if(icsk->icsk_ca_state != TCP_CA_Loss)
            {
                p->type = 3;  //FAST Retransmit
                //pr_info("FAST Restransmit index:%d:%d [%pI4:%d->%pI4:%d] Init seq %#x, current seq %#x actual %d\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->seq - p->init_seq );
            }
            else //if(icsk->icsk_ca_state == TCP_CA_Recovery)
            {
                p->type = 2; //SLOW Start Timeout
                //pr_info("TIMEOUT index:%d:%d [%pI4:%d->%pI4:%d] Init seq %#x, current seq %#x actual %d\n", k, p->index, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->seq - p->init_seq);
            }
            *pp = *p;

            tcp_probe3.head = (tcp_probe3.head + 1) & (bufsize - 1);
        }

        spin_unlock(&tcp_probe3.lock);

        wake_up(&tcp_probe3.wait);
    }
out:
    jprobe_return();
}

void jtcp_v4_send_check(struct sock *sk, struct sk_buff *skb)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct inet_sock *inet = inet_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    bool rxmit=false, fxmit=false;

    //---- Only update if port matches
    if (skb && ( port == 0 ||  ntohs(inet->inet_dport) == port ||  ntohs(inet->inet_sport) == port))  //tp->snd_cwnd != tcp_probe.lastcwnd)) {
    {
        int k=hash(inet, NULL);
        if(k>=SIZE || k<0)
            goto out;
        struct tcp_log *p = &logarr[k];

        //pr_info("Restransmit index:%d [%pI4:%d->%pI4:%d] Initial sequence number is %#x\n", k, &inet->inet_saddr, ntohs(inet->inet_sport), &inet->inet_daddr, ntohs(inet->inet_dport), p->init_seq);
        if(p->index==-1 ||  (skb->len<=80 && (TCP_SKB_CB(skb)->tcp_flags && TCPHDR_ACK)) || p->type==2 || p->type==3) //|| p->retrans_out) //|| p->snd_nxt == tp->snd_nxt)
           goto out;

        u32 oldretranshigh = p->retransmit_ahigh;

        fill_log(p, tp, skb, 0);

        if(p->retransmit_ahigh && p->pkt_aseq <= p->retransmit_ahigh)
        {
            if(p->retrans_stamp >= MIN_TIMEOUT)//!tp->flight_pkts)
                rxmit=true;
            else
                fxmit=true;
        }

        spin_lock(&tcp_probe1.lock);
        //--- If log fills, just silently drop

        if (tcp_probe_avail1() > 1)
        {
            //pr_info("TCP retransmit %pISpc -> %pISpc has been called \n", &p->src, &p->dst);
            struct tcp_log *pp = tcp_probe1.log + tcp_probe1.head;
             p->ptype=p->type;
             if(rxmit)
                p->type=12;
             else if(fxmit)
                p->type =13;
             else
                p->type=1;
             *pp = *p;

             tcp_probe1.head = (tcp_probe1.head + 1) & (bufsize - 1);
        }

        spin_unlock(&tcp_probe1.lock);

         wake_up(&tcp_probe1.wait);
    }
out:
    jprobe_return();
}

static struct jprobe tcp_jprobe1 =
{
    .kp = {
        .symbol_name	= "tcp_retransmit_skb",
    },
    .entry	= jtcp_retransmit_skb,
};

static struct jprobe tcp_jprobe2 =
{
    .kp = {
        .symbol_name	= "tcp_set_state",

    },
    .entry  = jtcp_set_state,
};

static struct jprobe tcp_jprobe3 =
{
    .kp = {
        .symbol_name	= "tcp_v4_send_check",
    },
    .entry	= jtcp_v4_send_check,
};

static struct jprobe tcp_jprobe4 =
{
    .kp = {
        .symbol_name    = "tcp_v4_do_rcv",
    },
    .entry      = jtcp_v4_do_rcv,
};


static int lossprobe_open1(struct inode *inode, struct file *file)
{
    /* Reset (empty) log */
    spin_lock_bh(&tcp_probe1.lock);
    tcp_probe1.head = tcp_probe1.tail = 0;
    spin_unlock_bh(&tcp_probe1.lock);

    return 0;
}

static int lossprobe_open2(struct inode *inode, struct file *file)
{
    /* Reset (empty) log */
    spin_lock_bh(&tcp_probe2.lock);
    tcp_probe2.head = tcp_probe2.tail = 0;
    spin_unlock_bh(&tcp_probe2.lock);

    return 0;
}

static int lossprobe_open3(struct inode *inode, struct file *file)
{
    /* Reset (empty) log */
    spin_lock_bh(&tcp_probe3.lock);
    tcp_probe3.head = tcp_probe3.tail = 0;
    spin_unlock_bh(&tcp_probe3.lock);

    return 0;
}

static int lossprobe_sprint1(char *tbuf, int n)
{
    const struct tcp_log *p = tcp_probe1.log + tcp_probe1.tail;
    struct timespec tv =  p->tspec; //ktime_to_timespec(p->tstamp);
    struct timespec tv1 = ktime_to_timespec(ktime_sub(p->tstamp, tcp_probe1.start));

    if(p->type==1)
            return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu XMIT %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
    if(p->type==12)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu RXMIT %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
    else if(p->type==13)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu FXMIT %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
	else if(p->type==4)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu OPEN %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
	else if(p->type==5)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu CLOSE %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                          p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);

}

static int lossprobe_sprint2(char *tbuf, int n)
{
    const struct tcp_log *p = tcp_probe2.log + tcp_probe2.tail;
    struct timespec tv =  p->tspec; //ktime_to_timespec(p->tstamp);
    struct timespec tv1 = ktime_to_timespec(ktime_sub(p->tstamp, tcp_probe2.start));


     if(p->type==6)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu RCV %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                        p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
	else if(p->type==7)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu RCVA %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
	else if(p->type==8)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu RACK %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq, p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
    else if(p->type==9)
    return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu DACK %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);

    else if(p->type==10)
    return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu OTOS %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
	else if(p->type==11)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu CTOS %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                          p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp,  p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
}

static int lossprobe_sprint3(char *tbuf, int n)
{
    const struct tcp_log *p = tcp_probe3.log + tcp_probe3.tail;
    struct timespec tv =  p->tspec; //ktime_to_timespec(p->tstamp);
    struct timespec tv1 = ktime_to_timespec(ktime_sub(p->tstamp, tcp_probe3.start));

    if(p->type==2)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu RXMIT %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
    else if(p->type==3)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu FXMIT %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
	else if(p->type==4)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu OPEN %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                         p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
	else if(p->type==5)
        return scnprintf(tbuf, n,
                         "%.2lu:%.2lu:%.2lu:%.6lu CLOSE %d %lu.%09lu %pI4 %d %pI4 %d %d %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %d %d %d %d %d %d %u %u %u %u %u\n",
                         ( ((tv.tv_sec / 3600) + 8) % (24) ) , (tv.tv_sec / 60) % (60), tv.tv_sec % 60, tv.tv_nsec / 1000,
                          p->index, (unsigned long)tv1.tv_sec, (unsigned long)tv1.tv_nsec,
                         &p->sip, ntohs(p->sport), &p->dip, ntohs(p->dport), p->length, p->cur_mss, p->pkt_count, p->snd_nxt, p->snd_una, p->rcv_nxt,
                         p->snd_cwnd, p->flight_pkts, p->ssthresh, p->snd_wnd, p->srtt, p->rttvar_us, p->rcv_wnd,
                         p->pkt_seq,p->ack_seq, p->retransmit_high, p->packets_out, p->retrans_out,  p->lost_out,
			             p->total_retrans, p->undo_retrans, p->lsndtime, p->rcv_tstamp, p->retrans_stamp, p->recovperiod, p->maxrecovperiod,
			             p->init_seq ,  p->pkt_aseq,  p->retransmit_ahigh, p->init_ack, p->pkt_aseq);
}

static ssize_t lossprobe_read1(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
    int error = 0;
    size_t cnt = 0;

    if (!buf)
    {
        pr_info("buffer unintialized proprely %u \n", len);
        return -EINVAL;
    }

    while (cnt < len)
    {
        char tbuf[256];
        int width;

        /* Wait for data in buffer */
        error = wait_event_interruptible(tcp_probe1.wait, tcp_probe_used1() > 0);
        if (error)
            break;

        spin_lock_bh(&tcp_probe1.lock);
        if (tcp_probe1.head == tcp_probe1.tail)
        {
            /* multiple readers race? */
            spin_unlock_bh(&tcp_probe1.lock);
            continue;
        }
        width = lossprobe_sprint1(tbuf, sizeof(tbuf));
        if (cnt + width < len)
            tcp_probe1.tail = (tcp_probe1.tail + 1) & (bufsize - 1);
        spin_unlock_bh(&tcp_probe1.lock);

        //pr_info("Probe has been printed in read has been called \n");

        /* if record greater than space available
           return partial buffer (so far) */
        if (cnt + width >= len)
            break;

        if (copy_to_user(buf + cnt, tbuf, width))
            return -EFAULT;
        cnt += width;
    }

    return cnt == 0 ? error : cnt;
}

static ssize_t lossprobe_read2(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
    int error = 0;
    size_t cnt = 0;

    if (!buf)
    {
        pr_info("buffer unintialized proprely %u \n", len);
        return -EINVAL;
    }

    while (cnt < len)
    {
        char tbuf[256];
        int width;

        /* Wait for data in buffer */
        error = wait_event_interruptible(tcp_probe2.wait, tcp_probe_used2() > 0);
        if (error)
            break;

        spin_lock_bh(&tcp_probe2.lock);
        if (tcp_probe2.head == tcp_probe2.tail)
        {
            /* multiple readers race? */
            spin_unlock_bh(&tcp_probe2.lock);
            continue;
        }
        width = lossprobe_sprint2(tbuf, sizeof(tbuf));
        if (cnt + width < len)
            tcp_probe2.tail = (tcp_probe2.tail + 1) & (bufsize - 1);
        spin_unlock_bh(&tcp_probe2.lock);

        //pr_info("Probe has been printed in read has been called \n");

        /* if record greater than space available
           return partial buffer (so far) */
        if (cnt + width >= len)
            break;

        if (copy_to_user(buf + cnt, tbuf, width))
            return -EFAULT;
        cnt += width;
    }

    return cnt == 0 ? error : cnt;
}

static ssize_t lossprobe_read3(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
    int error = 0;
    size_t cnt = 0;

    if (!buf)
    {
        pr_info("buffer unintialized proprely %u \n", len);
        return -EINVAL;
    }

    while (cnt < len)
    {
        char tbuf[256];
        int width;

        /* Wait for data in buffer */
        error = wait_event_interruptible(tcp_probe3.wait, tcp_probe_used3() > 0);
        if (error)
            break;

        spin_lock_bh(&tcp_probe3.lock);
        if (tcp_probe3.head == tcp_probe3.tail)
        {
            /* multiple readers race? */
            spin_unlock_bh(&tcp_probe3.lock);
            continue;
        }
        width = lossprobe_sprint3(tbuf, sizeof(tbuf));
        if (cnt + width < len)
            tcp_probe3.tail = (tcp_probe3.tail + 1) & (bufsize - 1);
        spin_unlock_bh(&tcp_probe3.lock);

        //pr_info("Probe has been printed in read has been called \n");

        /* if record greater than space available
           return partial buffer (so far) */
        if (cnt + width >= len)
            break;

        if (copy_to_user(buf + cnt, tbuf, width))
            return -EFAULT;
        cnt += width;
    }

    return cnt == 0 ? error : cnt;
}


static const struct file_operations lossprobe_fops1 =
{
    .owner	 = THIS_MODULE,
    .open	 = lossprobe_open1,
    .read    = lossprobe_read1,
    .llseek  = noop_llseek,
};

static const struct file_operations lossprobe_fops2 =
{
    .owner	 = THIS_MODULE,
    .open	 = lossprobe_open2,
    .read    = lossprobe_read2,
    .llseek  = noop_llseek,
};

static const struct file_operations lossprobe_fops3 =
{
    .owner	 = THIS_MODULE,
    .open	 = lossprobe_open3,
    .read    = lossprobe_read3,
    .llseek  = noop_llseek,
};

static __init int lossprobe_init(void)
{
    int ret = -ENOMEM, i;

    /* Warning: if the function signature (declaration) of tcp_v4_do_rcv or any probed function,
     * has been changed in the current kernel, you also have to change the signature of
     * jtcp_v4_do_rcv or j(other functions) being probed, otherwise you end up right here!
     */
    BUILD_BUG_ON(__same_type(tcp_v4_do_rcv, jtcp_v4_do_rcv == 0));
    BUILD_BUG_ON(__same_type(tcp_v4_send_check, jtcp_v4_send_check) == 0);
    BUILD_BUG_ON(__same_type(tcp_retransmit_skb, jtcp_retransmit_skb) == 0);
    BUILD_BUG_ON(__same_type(tcp_set_state, jtcp_set_state) == 0);


    init_waitqueue_head(&tcp_probe1.wait);
    spin_lock_init(&tcp_probe1.lock);

    init_waitqueue_head(&tcp_probe2.wait);
    spin_lock_init(&tcp_probe2.lock);

    //init_waitqueue_head(&tcp_probe3.wait);
    //spin_lock_init(&tcp_probe3.lock);

    if (bufsize == 0)
        return -EINVAL;

    bufsize = roundup_pow_of_two(bufsize);
    tcp_probe1.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
    if (!tcp_probe1.log)
        goto err0;

    tcp_probe2.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
    if (!tcp_probe2.log)
        goto err0;

    /*tcp_probe3.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
    if (!tcp_probe3.log)
        goto err0;*/

    if (!proc_create(procname1, S_IRUSR, init_net.proc_net, &lossprobe_fops1))
        goto err0;

    if (!proc_create(procname2, S_IRUSR, init_net.proc_net, &lossprobe_fops2))
        goto err0;

     /*if (!proc_create(procname3, S_IRUSR, init_net.proc_net, &lossprobe_fops3))
        goto err0;*/

    tcp_probe1.start = tcp_probe2.start  = ktime_get(); //= tcp_probe3.start

    /*ret = register_jprobe(&tcp_jprobe1);
    if (ret)
        goto err1;*/

    ret = register_jprobe(&tcp_jprobe2);
    if (ret)
        goto err1;

    ret = register_jprobe(&tcp_jprobe3);
    if (ret)
        goto err1;

    ret = register_jprobe(&tcp_jprobe4);
    if (ret)
        goto err1;


    for(i=0;i<SIZE;i++)
    {
        reset_log(&logarr[i]);
    }


    get_random_bytes(&hash_seed, sizeof(u32));


    pr_info("probe registered (port=%d, bufsize=%u, size=%u, max_int=%u)\n", port, bufsize, SIZE, MAX_INT);
    return 0;
err1:
    pr_info("Could not register the requested jprobe\n");
    remove_proc_entry(procname1, init_net.proc_net);
    remove_proc_entry(procname2, init_net.proc_net);
    //remove_proc_entry(procname3, init_net.proc_net);

err0:
    pr_info("Could not allocate log or create PROC file\n");
    kfree(tcp_probe1.log);
    kfree(tcp_probe2.log);
    //kfree(tcp_probe3.log);

    return ret;
}
module_init(lossprobe_init);

static __exit void lossprobe_exit(void)
{
   remove_proc_entry(procname1, init_net.proc_net);

   remove_proc_entry(procname2, init_net.proc_net);

   //remove_proc_entry(procname3, init_net.proc_net);

    //unregister_jprobe(&tcp_jprobe1);
    unregister_jprobe(&tcp_jprobe2);
    unregister_jprobe(&tcp_jprobe3);
    unregister_jprobe(&tcp_jprobe4);

    kfree(tcp_probe1.log);
    kfree(tcp_probe2.log);
    //kfree(tcp_probe3.log);

}
module_exit(lossprobe_exit);
