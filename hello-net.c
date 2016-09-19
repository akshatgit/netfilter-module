#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>

#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
#define __KERNEL__

#include <linux/ip.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");              ///< The license type -- this affects runtime behavior
MODULE_AUTHOR("Akshat Sinha");      ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Hello world Netfilter-module!");  ///< The description -- see modinfo
MODULE_VERSION("0.1");              ///< The version of the module
static struct nf_hook_ops nfho;         //struct holding set of hook function options

//function to be called by hook
//unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
unsigned int hook_func(void *priv, struct sk_buff *skb,  const struct nf_hook_state *state)
{
    struct iphdr    * iph;
    struct tcphdr   * tcph;
    if (skb)
    {
        iph = ip_hdr(skb);
        if (iph && iph->protocol && (iph->protocol == IPPROTO_TCP))
        {
            tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);

            if ((tcph->source))
            {
                if(tcph->syn & (!(tcph->ack | tcph->urg | tcph->ack | tcph->psh | tcph->rst | tcph->fin)))
                {
                  printk(KERN_INFO "Syn scan detected\n");
                }
                else if(!tcph->syn && !tcph->ack && tcph->urg && !tcph->ack && tcph->psh && !tcph->rst && tcph->fin)
                {
                  printk(KERN_INFO "Xmas scan detected\n");
                }
                else if(!(tcph->syn | tcph->ack | tcph->urg | tcph->ack | tcph->psh | tcph->rst | tcph->fin))
                {
                  printk(KERN_INFO "Null scan detected\n");
                }
                else if(!tcph->syn && !tcph->ack && !tcph->urg && !tcph->ack && !tcph->psh && !tcph->rst && tcph->fin)
                {
                  printk(KERN_INFO "Fin scan detected\n");
                }
            }
        }
    }
    return NF_ACCEPT;
}


//Called when module loaded using 'insmod'
int init_module()
{
  int result;
  nfho.hook   = (nf_hookfn *) hook_func;
  nfho.hooknum    = NF_IP_POST_ROUTING;
  nfho.pf     = PF_INET;
  nfho.priority   = NF_IP_PRI_FIRST;
  result = nf_register_hook(&nfho);

  if(result)
  {
      printk(KERN_INFO "error !\n");
      return 1;
  }

  printk(KERN_INFO "Module added\n");
  return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);                     //cleanup – unregister hook
  printk(KERN_INFO "Module removed");
}
