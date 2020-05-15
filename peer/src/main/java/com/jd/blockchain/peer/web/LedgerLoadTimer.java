/**
 * Copyright: Copyright 2016-2020 JD.COM All Right Reserved
 * FileName: com.jd.blockchain.peer.web.ScheduledTasks
 * Author: shaozhuguang
 * Department: 区块链研发部
 * Date: 2019/1/7 上午11:12
 * Description:
 */
package com.jd.blockchain.peer.web;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.jd.blockchain.consensus.service.NodeServer;
import com.jd.blockchain.crypto.HashDigest;
import com.jd.blockchain.ledger.core.LedgerManage;
import com.jd.blockchain.peer.ConsensusManage;
import com.jd.blockchain.peer.LedgerBindingConfigAware;
import com.jd.blockchain.peer.PeerServerBooter;
import com.jd.blockchain.tools.initializer.LedgerBindingConfig;

import com.jd.blockchain.tools.initializer.web.LedgerBindingConfigException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.io.ClassPathResource;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.InputStream;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static com.jd.blockchain.peer.PeerServerBooter.LEDGER_BIND_CONFIG_NAME;

/**
 *
 * @author shaozhuguang
 * @create 2019/1/7
 * @since 1.0.0
 */
@Component
@EnableScheduling
public class LedgerLoadTimer implements ApplicationContextAware {

    private static Logger LOGGER = LoggerFactory.getLogger(LedgerLoadTimer.class);

    /**
     * 账本加载线程，单线程，内部进行判断，防止账本重新加载
     */
    private static final ExecutorService ledgerLoadExecutor = initLedgerLoadExecutor();

    private static final Lock lock = new ReentrantLock();

    private ApplicationContext applicationContext;

    @Autowired
    private LedgerManage ledgerManager;

    //每5秒执行一次
    @Scheduled(cron = "*/5 * * * * * ")
    public void ledgerLoad() {

        lock.lock();
        try {
            LOGGER.debug("--- Ledger loader tasks start... ");
            try {
                LedgerBindingConfig ledgerBindingConfig = loadLedgerBindingConfig();
                if (ledgerBindingConfig == null) {
                    // print debug
                    LOGGER.error("Can not load any ledgerBindingConfigs !!!");
                    return;
                }

                HashDigest[] totalLedgerHashs = ledgerBindingConfig.getLedgerHashs();
                Set<HashDigest> existedHashSet = existedHashSet();

                Set<HashDigest> newAddHashs = new HashSet<>();
                for (HashDigest ledgerHash : totalLedgerHashs) {
                    if (!existedHashSet.contains(ledgerHash)) {
                        newAddHashs.add(ledgerHash);
                    }
                }
                if (!newAddHashs.isEmpty()) {
                    // 由线程单独执行
                    ledgerLoadExecutor.execute(new LedgerLoadRunnable(newAddHashs, ledgerBindingConfig));
                } else {
                    LOGGER.debug("All ledgers is newest!!!");
                }
            } catch (Exception e) {
                LOGGER.error("--- Ledger loader execute error !!!", e);
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    private LedgerBindingConfig loadLedgerBindingConfig() throws Exception {
        LedgerBindingConfig ledgerBindingConfig = null;
        String ledgerBindConfigFile = PeerServerBooter.ledgerBindConfigFile;
        LOGGER.debug("--- Load " + LEDGER_BIND_CONFIG_NAME + " path = {}",
                ledgerBindConfigFile == null ? "Default" : ledgerBindConfigFile);
        if (ledgerBindConfigFile == null) {
            ClassPathResource configResource = new ClassPathResource(LEDGER_BIND_CONFIG_NAME);
            if (configResource.exists()) {
                try (InputStream in = configResource.getInputStream()) {
                    ledgerBindingConfig = LedgerBindingConfig.resolve(in);
                } catch (LedgerBindingConfigException e) {
                    LOGGER.debug("Load ledgerBindConfigFile content is empty !!!");
                }
            }
        } else {
            File file = new File(ledgerBindConfigFile);
            if (file.exists()) {
                try {
                    ledgerBindingConfig = LedgerBindingConfig.resolve(file);
                } catch (LedgerBindingConfigException e) {
                    LOGGER.debug("Load ledgerBindConfigFile content is empty !!!");
                }
            }
        }
        return ledgerBindingConfig;
    }

    private Set<HashDigest> existedHashSet() {
        Set<HashDigest> existedHashSet = new HashSet<>();
        HashDigest[] existLedgerHashs = ledgerManager.getLedgerHashs();
        if (existLedgerHashs != null) {
            existedHashSet.addAll(Arrays.asList(existLedgerHashs));
        }
        return existedHashSet;
    }

    private class LedgerLoadRunnable implements Runnable {

        Set<HashDigest> newAddHashs;
        LedgerBindingConfig ledgerBindingConfig;

        LedgerLoadRunnable(Set<HashDigest> newAddHashs, LedgerBindingConfig ledgerBindingConfig) {
            this.newAddHashs = newAddHashs;
            this.ledgerBindingConfig = ledgerBindingConfig;
        }

        @Override
        public void run() {
            // 建立共识网络；
            Map<String, LedgerBindingConfigAware> bindingConfigAwares = applicationContext.getBeansOfType(LedgerBindingConfigAware.class);
            List<NodeServer> nodeServers = new ArrayList<>();
            Set<HashDigest> existedHashSet = existedHashSet();
            for (HashDigest ledgerHash : newAddHashs) {
                //recheck
                if (existedHashSet.contains(ledgerHash)) {
                    LOGGER.info("--- Ledger [{}] has been inited ---", ledgerHash.toBase58());
                    continue;
                }
                LOGGER.info("--- New ledger [{}] need to be init... ", ledgerHash.toBase58());
                for (LedgerBindingConfigAware aware : bindingConfigAwares.values()) {
                    nodeServers.add(aware.setConfig(ledgerBindingConfig.getLedger(ledgerHash), ledgerHash));
                }
            }
            if (!nodeServers.isEmpty()) {
                // 启动指定NodeServer节点
                ConsensusManage consensusManage = applicationContext.getBean(ConsensusManage.class);
                for (NodeServer nodeServer : nodeServers) {
                    consensusManage.runRealm(nodeServer);
                }
            }
        }
    }

    private static ThreadPoolExecutor initLedgerLoadExecutor() {
        ThreadFactory threadFactory = new ThreadFactoryBuilder()
                .setNameFormat("ledger-loader-%d").build();

        return new ThreadPoolExecutor(1, 1,
                60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1024),
                threadFactory,
                new ThreadPoolExecutor.AbortPolicy());
    }
}