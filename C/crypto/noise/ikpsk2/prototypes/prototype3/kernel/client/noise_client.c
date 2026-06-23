#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/curve25519.h>
#include "handshake.h"

MODULE_LICENSE("GPL v2");

struct noise_test_bridge {
    struct semaphore sem_client_to_server;
    struct semaphore sem_server_to_client;
    struct ikpsk2_msg1 msg1;
    struct ikpsk2_msg2 msg2;
};
extern struct noise_test_bridge g_bridge;

static struct task_struct *client_thread;

static int noise_client_fn(void *data)
{
    struct noise_peer *client_peer;
    u8 server_fake_priv[NOISE_PUBLIC_KEY_LEN];

    client_peer = kzalloc(sizeof(struct noise_peer), GFP_KERNEL);
    if (!client_peer) return -ENOMEM;

    client_peer->handshake.static_identity = kzalloc(sizeof(struct noise_identity), GFP_KERNEL);
    if (!client_peer->handshake.static_identity) {
        kfree(client_peer);
        return -ENOMEM;
    }

    memset(client_peer->handshake.static_identity->static_private, 0x42, NOISE_PUBLIC_KEY_LEN);
    curve25519(client_peer->handshake.static_identity->static_public, 
               client_peer->handshake.static_identity->static_private, 
               curve25519_base_point);

    memset(server_fake_priv, 0x24, NOISE_PUBLIC_KEY_LEN);
    curve25519(client_peer->handshake.remote_static, 
               server_fake_priv, 
               curve25519_base_point);

    memset(client_peer->handshake.psk, 0x99, NOISE_SYMMETRIC_KEY_LEN);

    pr_info("Client Creating initiation message 1\n");

    noise_handshake_create_initiation(&g_bridge.msg1, &client_peer->handshake);
    pr_info("Client Message 1 created\n");
    pr_info("Client Sending message 1\n");

    up(&g_bridge.sem_client_to_server);

    pr_info("Client Message1 sent\n");
    pr_info("Client Waiting for message 2\n");
    if (!down_interruptible(&g_bridge.sem_server_to_client)) {
        
        pr_info("Client Message 2 received and being processed\n");
        handshake_consume_response(&g_bridge.msg2, client_peer);

        begin_session(client_peer);
        pr_info("Client handshake done\n");

        print_hex_dump(KERN_INFO, "Client Sending Key : ", DUMP_PREFIX_NONE, 
                       32, 1, client_peer->symmetric_keys.sending_key, NOISE_SYMMETRIC_KEY_LEN, false);
                       
        print_hex_dump(KERN_INFO, "Client Receiving Key : ", DUMP_PREFIX_NONE, 
                       32, 1, client_peer->symmetric_keys.receiving_key, NOISE_SYMMETRIC_KEY_LEN, false);
    }

    kfree(client_peer->handshake.static_identity);
    kfree(client_peer);

    while (!kthread_should_stop()) {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(HZ);
    }

    return 0;
}

static int __init noise_client_init(void)
{
    client_thread = kthread_run(noise_client_fn, NULL, "knoise_client");
    return 0;
}

static void __exit noise_client_exit(void)
{
    if (client_thread) kthread_stop(client_thread);
}

module_init(noise_client_init);
module_exit(noise_client_exit);