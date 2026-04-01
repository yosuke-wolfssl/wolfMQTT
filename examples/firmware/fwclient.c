/* fwclient.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfMQTT is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"

/* This example only works with ENABLE_MQTT_TLS (wolfSSL library). */
#if defined(ENABLE_MQTT_TLS)
    #if !defined(WOLFSSL_USER_SETTINGS) && !defined(USE_WINDOWS_API)
        #include <wolfssl/options.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
#endif

#include "fwclient.h"
#include "firmware.h"
#include "examples/mqttexample.h"
#include "examples/mqttnet.h"

/* Configuration */
#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE         FIRMWARE_MAX_PACKET
#endif

/* Locals */
static int mStopRead = 0;
static int mTestDone = 0;
static byte mMsgBuf[FIRMWARE_MAX_BUFFER];

typedef struct FwClientTransfer_s {
    word32 total_len;
    word32 bytes_written;
    word16 expected_chunk;
    int active;
#if !defined(NO_FILESYSTEM)
    FILE* fp;
#endif
} FwClientTransfer;

static FwClientTransfer mTransfer;

static void fw_transfer_reset(void)
{
#if !defined(NO_FILESYSTEM)
    if (mTransfer.fp != NULL) {
        fclose(mTransfer.fp);
        mTransfer.fp = NULL;
    }
#endif
    XMEMSET(&mTransfer, 0, sizeof(mTransfer));
}

static int fw_transfer_begin(MQTTCtx* mqttCtx, word32 total_len)
{
    if (mqttCtx == NULL || total_len == 0) {
        return EXIT_FAILURE;
    }

    fw_transfer_reset();
    mTransfer.total_len = total_len;
    mTransfer.active = 1;

#if !defined(NO_FILESYSTEM)
    mTransfer.fp = fopen(mqttCtx->pub_file, "wb");
    if (mTransfer.fp == NULL) {
        PRINTF("File %s open error", mqttCtx->pub_file);
        fw_transfer_reset();
        return EXIT_FAILURE;
    }
#endif

    PRINTF("Firmware transfer started: total %u bytes", total_len);
    return 0;
}

static int fw_transfer_write_chunk(const byte* chunk_data, word16 chunk_len)
{
#if !defined(NO_FILESYSTEM)
    int written;
#endif

    if (!mTransfer.active || chunk_data == NULL || chunk_len == 0) {
        return EXIT_FAILURE;
    }

#if !defined(NO_FILESYSTEM)
    written = (int)fwrite(chunk_data, 1, chunk_len, mTransfer.fp);
    if (written != chunk_len) {
        PRINTF("Chunk file write error: %d", written);
        return EXIT_FAILURE;
    }
#endif

    mTransfer.bytes_written += chunk_len;

    if (mTransfer.bytes_written > mTransfer.total_len) {
        PRINTF("Chunk exceeds expected total length");
        return EXIT_FAILURE;
    }

    return 0;
}

static int fw_transfer_finish(MQTTCtx* mqttCtx)
{
    (void)mqttCtx;

    PRINTF("Firmware transfer complete: %u bytes", mTransfer.bytes_written);
    fw_transfer_reset();

    if (mqttCtx->test_mode) {
        mTestDone = 1;
    } else {
        mStopRead = 1;
    }

    return 0;
}

static int fw_message_process(MQTTCtx *mqttCtx, const byte* buffer, word32 len)
{
    const MessageHeader* header;
    const byte* payload;
    word32 payload_len;

    if (mqttCtx == NULL || buffer == NULL) {
        return EXIT_FAILURE;
    }

    if (len < sizeof(MessageHeader)) {
        PRINTF("Chunk too small: %u", len);
        return EXIT_FAILURE;
    }

    header = (const MessageHeader*)buffer;
    payload = buffer + sizeof(MessageHeader);
    payload_len = len - sizeof(MessageHeader);

    if (header->chunkSize != payload_len) {
        PRINTF("Chunk size mismatch: header %u, payload %u",
            header->chunkSize, payload_len);
        return EXIT_FAILURE;
    }

    if (header->totalLen == 0) {
        PRINTF("Invalid total length 0");
        return EXIT_FAILURE;
    }

    if (header->chunkNumber == 0) {
        if (fw_transfer_begin(mqttCtx, header->totalLen) != 0) {
            return EXIT_FAILURE;
        }
    }

    if (!mTransfer.active) {
        PRINTF("Received chunk without active transfer");
        return EXIT_FAILURE;
    }

    if (header->totalLen != mTransfer.total_len) {
        PRINTF("Transfer total length changed: %u -> %u",
            mTransfer.total_len, header->totalLen);
        fw_transfer_reset();
        return EXIT_FAILURE;
    }

    if (header->chunkNumber < mTransfer.expected_chunk) {
        /* Duplicate chunk from retransmit; ignore if already committed. */
        PRINTF("Ignoring duplicate chunk %u", header->chunkNumber);
        return 0;
    }

    if (header->chunkNumber != mTransfer.expected_chunk) {
        PRINTF("Out-of-order chunk: expected %u, got %u",
            mTransfer.expected_chunk, header->chunkNumber);
        fw_transfer_reset();
        return EXIT_FAILURE;
    }

    if (fw_transfer_write_chunk(payload, header->chunkSize) != 0) {
        fw_transfer_reset();
        return EXIT_FAILURE;
    }

    PRINTF("Firmware chunk %u: %u bytes (%u/%u)",
        header->chunkNumber,
        header->chunkSize,
        mTransfer.bytes_written,
        mTransfer.total_len);

    mTransfer.expected_chunk++;

    if (mTransfer.bytes_written == mTransfer.total_len) {
        return fw_transfer_finish(mqttCtx);
    }

    return 0;
}

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;

    if (msg_new) {
        if (XSTRNCMP(msg->topic_name, mqttCtx->topic_name,
            msg->topic_name_len) != 0) {
            return MQTT_CODE_SUCCESS;
        }

        if (msg->total_len > sizeof(mMsgBuf)) {
            PRINTF("Incoming publish exceeds firmware message buffer: %u",
                msg->total_len);
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }

        PRINTF("MQTT Firmware Chunk Message: Qos %d, Len %u",
            msg->qos, msg->total_len);
    }

    if ((msg->buffer_pos + msg->buffer_len) > sizeof(mMsgBuf)) {
        PRINTF("Incoming payload chunk exceeds message buffer");
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    XMEMCPY(&mMsgBuf[msg->buffer_pos], msg->buffer, msg->buffer_len);

    if (msg_done) {
        if (fw_message_process(mqttCtx, mMsgBuf, msg->total_len) != 0) {
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

int fwclient_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS, i;

    switch(mqttCtx->stat) {
        case WMQ_BEGIN:
        {
            PRINTF("MQTT Firmware Client: QoS %d, Use TLS %d", mqttCtx->qos, mqttCtx->use_tls);
        }
        FALL_THROUGH;

        case WMQ_NET_INIT:
        {
            mqttCtx->stat = WMQ_NET_INIT;

            /* Initialize Network */
            rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Net Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* setup tx/rx buffers */
            mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
            mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
        }
        FALL_THROUGH;

        case WMQ_INIT:
        {
            mqttCtx->stat = WMQ_INIT;

            /* Initialize MqttClient structure */
            rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net,
                mqtt_message_cb,
                mqttCtx->tx_buf, MAX_BUFFER_SIZE,
                mqttCtx->rx_buf, MAX_BUFFER_SIZE,
                mqttCtx->cmd_timeout_ms);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            mqttCtx->client.ctx = mqttCtx;
        }
        FALL_THROUGH;

        case WMQ_TCP_CONN:
        {
            mqttCtx->stat = WMQ_TCP_CONN;

            /* Connect to broker */
            rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
                mqttCtx->port, DEFAULT_CON_TIMEOUT_MS,
                mqttCtx->use_tls, mqtt_tls_cb);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Connect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Build connect packet */
            XMEMSET(&mqttCtx->connect, 0, sizeof(MqttConnect));
            mqttCtx->connect.keep_alive_sec = mqttCtx->keep_alive_sec;
            mqttCtx->connect.clean_session = mqttCtx->clean_session;
            mqttCtx->connect.client_id = mqttCtx->client_id;
            if (mqttCtx->enable_lwt) {
                /* Send client id in LWT payload */
                mqttCtx->lwt_msg.qos = mqttCtx->qos;
                mqttCtx->lwt_msg.retain = 0;
                mqttCtx->lwt_msg.topic_name = FIRMWARE_TOPIC_NAME"lwttopic";
                mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
                mqttCtx->lwt_msg.total_len = (word16)XSTRLEN(mqttCtx->client_id);
            }

            /* Optional authentication */
            mqttCtx->connect.username = mqttCtx->username;
            mqttCtx->connect.password = mqttCtx->password;
        }
        FALL_THROUGH;

        case WMQ_MQTT_CONN:
        {
            mqttCtx->stat = WMQ_MQTT_CONN;

            /* Send Connect and wait for Connect Ack */
            rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Connect: Proto (%s), %s (%d)",
                MqttClient_GetProtocolVersionString(&mqttCtx->client),
                MqttClient_ReturnCodeToString(rc), rc);

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx->connect.ack.return_code,
                (mqttCtx->connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Build list of topics */
            mqttCtx->topics[0].topic_filter = mqttCtx->topic_name;
            mqttCtx->topics[0].qos = mqttCtx->qos;

            /* Subscribe Topic */
            XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));
            mqttCtx->subscribe.packet_id = mqtt_get_packetid();
            mqttCtx->subscribe.topic_count = 1;
            mqttCtx->subscribe.topics = mqttCtx->topics;
        }
        FALL_THROUGH;

        case WMQ_SUB:
        {
            mqttCtx->stat = WMQ_SUB;

            rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Subscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);

            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
            for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
                MqttTopic *topic = &mqttCtx->subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    topic->topic_filter,
                    topic->qos,
                    topic->return_code);
            }
            /* Read Loop */
            PRINTF("MQTT Waiting for message...");
        }
        FALL_THROUGH;

        case WMQ_WAIT_MSG:
        {
            mqttCtx->stat = WMQ_WAIT_MSG;

            do {
                /* Try and read packet */
                rc = MqttClient_WaitMessage(&mqttCtx->client,
                                                  mqttCtx->cmd_timeout_ms);

            #ifdef WOLFMQTT_NONBLOCK
                /* Track elapsed time with no activity and trigger timeout */
                rc = mqtt_check_timeout(rc, &mqttCtx->start_sec,
                    mqttCtx->cmd_timeout_ms/1000);
            #endif

                /* check return code */
                if (rc == MQTT_CODE_CONTINUE) {
                    return rc;
                }

                /* check for test mode */
                if (mStopRead || mTestDone) {
                    rc = MQTT_CODE_SUCCESS;
                    mqttCtx->stat = WMQ_DISCONNECT;
                    PRINTF("MQTT Exiting...");
                    break;
                }

                if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    if (mqttCtx->test_mode) {
                        PRINTF("Timeout in test mode, exit early!");
                        mTestDone = 1;
                    }
                    /* Keep Alive */
                    PRINTF("Keep-alive timeout, sending ping");

                    rc = MqttClient_Ping_ex(&mqttCtx->client, &mqttCtx->ping);
                    if (rc == MQTT_CODE_CONTINUE) {
                        return rc;
                    }
                    else if (rc != MQTT_CODE_SUCCESS) {
                        PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                            MqttClient_ReturnCodeToString(rc), rc);
                        break;
                    }
                }
                else if (rc != MQTT_CODE_SUCCESS) {
                    /* There was an error */
                    PRINTF("MQTT Message Wait: %s (%d)",
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
                }

                /* Exit if test mode */
                if (mqttCtx->test_mode) {
                    break;
                }
            } while (1);

            /* Check for error */
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

        case WMQ_DISCONNECT:
        {
            /* Disconnect */
            rc = MqttClient_Disconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

        case WMQ_NET_DISCONNECT:
        {
            mqttCtx->stat = WMQ_NET_DISCONNECT;

            rc = MqttClient_NetDisconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }
        FALL_THROUGH;

        case WMQ_DONE:
        {
            mqttCtx->stat = WMQ_DONE;
            rc = mqttCtx->return_code;
            goto exit;
        }

        case WMQ_PUB:
        case WMQ_UNSUB:
        case WMQ_PING:
        default:
            rc = MQTT_CODE_ERROR_STAT;
            goto exit;
    } /* switch */

disconn:
    mqttCtx->stat = WMQ_NET_DISCONNECT;
    mqttCtx->return_code = rc;
    rc = MQTT_CODE_CONTINUE;

exit:

    if (rc != MQTT_CODE_CONTINUE) {
        fw_transfer_reset();

        /* Free resources */
        if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
        if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

        /* Cleanup network */
        MqttClientNet_DeInit(&mqttCtx->net);

        MqttClient_DeInit(&mqttCtx->client);
    }

    return rc;
}


/* so overall tests can pull in test function */
#ifdef USE_WINDOWS_API
    #include <windows.h> /* for ctrl handler */

    static BOOL CtrlHandler(DWORD fdwCtrlType)
    {
        if (fdwCtrlType == CTRL_C_EVENT) {
            mStopRead = 1;
            PRINTF("Received Ctrl+c");
            return TRUE;
        }
        return FALSE;
    }
#elif HAVE_SIGNAL
    #include <signal.h>
    static void sig_handler(int signo)
    {
        if (signo == SIGINT) {
            mStopRead = 1;
            PRINTF("Received SIGINT");
        }
    }
#endif

#if defined(NO_MAIN_DRIVER)
int fwclient_main(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
    int rc;
    MQTTCtx mqttCtx;

    /* init defaults */
    mqtt_init_ctx(&mqttCtx);
    mqttCtx.app_name = "fwclient";
    mqttCtx.client_id = mqtt_append_random(FIRMWARE_CLIIENT_ID,
        (word32)XSTRLEN(FIRMWARE_CLIIENT_ID));
    mqttCtx.dynamicClientId = 1;
    mqttCtx.topic_name = FIRMWARE_TOPIC_NAME;
    mqttCtx.qos = FIRMWARE_MQTT_QOS;
    mqttCtx.pub_file = FIRMWARE_DEF_SAVE_AS;

    /* parse arguments */
    rc = mqtt_parse_args(&mqttCtx, argc, argv);
    if (rc != 0) {
        return rc;
    }

#ifdef USE_WINDOWS_API
    if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
        PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
    }
#elif HAVE_SIGNAL
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        PRINTF("Can't catch SIGINT");
    }
#endif

    do {
        rc = fwclient_test(&mqttCtx);
    } while (!mStopRead && rc == MQTT_CODE_CONTINUE);

    mqtt_free_ctx(&mqttCtx);

    return (rc == 0) ? 0 : EXIT_FAILURE;
}
