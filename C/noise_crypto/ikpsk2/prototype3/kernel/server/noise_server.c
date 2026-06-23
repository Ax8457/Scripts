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

struct noise_test_bridge g_bridge;
EXPORT_SYMBOL(g_bridge);

static struct task_struct *server_thread;

static int noise_server_fn(void *data)
{
    struct noise_peer *server_peer;
    u8 client_fake_priv[NOISE_PUBLIC_KEY_LEN];
    bool handshake_done = false;

    server_peer = kzalloc(sizeof(struct noise_peer), GFP_KERNEL);
    if (!server_peer) return -ENOMEM;

    server_peer->handshake.static_identity = kzalloc(sizeof(struct noise_identity), GFP_KERNEL);
    if (!server_peer->handshake.static_identity) {
        kfree(server_peer);
        return -ENOMEM;
    }

    memset(server_peer->handshake.static_identity->static_private, 0x24, NOISE_PUBLIC_KEY_LEN);
    curve25519(server_peer->handshake.static_identity->static_public, 
               server_peer->handshake.static_identity->static_private, 
               curve25519_base_point);

    memset(client_fake_priv, 0x42, NOISE_PUBLIC_KEY_LEN);
    curve25519(server_peer->handshake.remote_static, 
               client_fake_priv, 
               curve25519_base_point);

    memset(server_peer->handshake.psk, 0x99, NOISE_SYMMETRIC_KEY_LEN);

    pr_info("Server Waiting for message 1\n");

    while (!kthread_should_stop() && !handshake_done) {
        if (down_interruptible(&g_bridge.sem_client_to_server))
            break;

        pr_info("Server Message 1 receiving\n");
        pr_info("Server Message 1 is being processed\n");
        handshake_consume_initiation(&g_bridge.msg1, server_peer);

        pr_info("Server Message 1 processed\n");
        pr_info("Server Creating message 2\n");
        handshake_create_response(&g_bridge.msg2, server_peer);

        pr_info("Server Message2 created\n");

        up(&g_bridge.sem_server_to_client);

        begin_session(server_peer);
        pr_info("Server Handshake done \n");

        print_hex_dump(KERN_INFO, "Server Sending Key : ", DUMP_PREFIX_NONE, 
                       32, 1, server_peer->symmetric_keys.sending_key, NOISE_SYMMETRIC_KEY_LEN, false);
                       
        print_hex_dump(KERN_INFO, "Server Receiving Key : ", DUMP_PREFIX_NONE, 
                       32, 1, server_peer->symmetric_keys.receiving_key, NOISE_SYMMETRIC_KEY_LEN, false);

        handshake_done = true;
    }

    kfree(server_peer->handshake.static_identity);
    kfree(server_peer);

    while (!kthread_should_stop()) {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(HZ);
    }

    return 0;
}

static int __init noise_server_init(void)
{
    sema_init(&g_bridge.sem_client_to_server, 0);
    sema_init(&g_bridge.sem_server_to_client, 0);
    server_thread = kthread_run(noise_server_fn, NULL, "knoise_server");
    return 0;
}

static void __exit noise_server_exit(void)
{
    if (server_thread) kthread_stop(server_thread);
}

module_init(noise_server_init);
module_exit(noise_server_exit);