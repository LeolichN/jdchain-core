/**
 * Copyright: Copyright 2016-2020 JD.COM All Right Reserved
 * FileName: com.jd.blockchain.consensus.mq.client.MsgQueueConsensusClient
 * Author: shaozhuguang
 * Department: 区块链研发部
 * Date: 2018/12/12 下午3:23
 * Description:
 */
package com.jd.blockchain.consensus.mq.client;

import com.jd.blockchain.consensus.MessageService;
import com.jd.blockchain.consensus.client.ClientSettings;
import com.jd.blockchain.consensus.client.ConsensusClient;
import com.jd.blockchain.consensus.mq.consumer.MsgQueueConsumer;
import com.jd.blockchain.consensus.mq.factory.MsgQueueFactory;
import com.jd.blockchain.consensus.mq.producer.MsgQueueProducer;
import com.jd.blockchain.consensus.mq.settings.MsgQueueClientSettings;
import com.jd.blockchain.consensus.mq.settings.MsgQueueNetworkSettings;

/**
 * @author shaozhuguang
 * @create 2018/12/12
 * @since 1.0.0
 */

public class MsgQueueConsensusClient implements ConsensusClient {

    private boolean isConnected;

    private DefaultMessageTransmitter transmitter;

    private MsgQueueNetworkSettings msgQueueNetworkSettings;

    private MsgQueueClientSettings clientSettings;

    public MsgQueueConsensusClient setClientSettings(MsgQueueClientSettings clientSettings) {
        this.clientSettings = clientSettings;
        return this;
    }

    public MsgQueueConsensusClient setMsgQueueNetworkSettings(MsgQueueNetworkSettings msgQueueNetworkSettings) {
        this.msgQueueNetworkSettings = msgQueueNetworkSettings;
        return this;
    }

    public void init() {
        String server = msgQueueNetworkSettings.getServer();
        String txTopic = msgQueueNetworkSettings.getTxTopic();
        String txResultTopic = msgQueueNetworkSettings.getTxResultTopic();
        String msgTopic = msgQueueNetworkSettings.getMsgTopic();
        String msgResultTopic = msgQueueNetworkSettings.getMsgResultTopic();

        MsgQueueProducer txProducer = MsgQueueFactory.newProducer(server, txTopic, false);
        MsgQueueProducer msgProducer = MsgQueueFactory.newProducer(server, msgTopic, false);
        MsgQueueConsumer txResultConsumer = MsgQueueFactory.newConsumer(server, txResultTopic, false);
        MsgQueueConsumer msgResultConsumer = MsgQueueFactory.newConsumer(server, msgResultTopic, false);

        transmitter = new DefaultMessageTransmitter()
                .setTxProducer(txProducer)
                .setMsgProducer(msgProducer)
                .setTxResultConsumer(txResultConsumer)
                .setMsgResultConsumer(msgResultConsumer)
        ;
    }

    @Override
    public MessageService getMessageService() {
        return transmitter;
    }

    @Override
    public ClientSettings getSettings() {
        return clientSettings;
    }

    @Override
    public boolean isConnected() {
        return isConnected;
    }

    @Override
    public synchronized void connect() {
        if (!isConnected) {
            try {
                this.transmitter.connect();
                isConnected = true;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public synchronized void close() {
        if (isConnected) {
            transmitter.close();
            isConnected = false;
        }
    }
}