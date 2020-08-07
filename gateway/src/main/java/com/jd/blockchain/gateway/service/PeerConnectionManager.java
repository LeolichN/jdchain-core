package com.jd.blockchain.gateway.service;

import javax.annotation.PreDestroy;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.jd.blockchain.crypto.HashDigest;
import com.jd.blockchain.gateway.event.EventListener;
import com.jd.blockchain.gateway.event.EventListenerService;
import com.jd.blockchain.gateway.event.PullEventListener;
import com.jd.blockchain.sdk.BlockchainService;
import com.jd.blockchain.sdk.PeerBlockchainService;
import com.jd.blockchain.sdk.service.PeerServiceProxy;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.jd.blockchain.crypto.AsymmetricKeypair;
import com.jd.blockchain.gateway.PeerConnector;
import com.jd.blockchain.gateway.PeerService;
import com.jd.blockchain.sdk.service.PeerBlockchainServiceFactory;
import com.jd.blockchain.transaction.BlockchainQueryService;
import com.jd.blockchain.transaction.TransactionService;
import com.jd.blockchain.utils.net.NetworkAddress;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

@Component
public class PeerConnectionManager implements PeerService, PeerConnector, EventListenerService {

	private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(PeerConnectionManager.class);

	/**
	 * 30秒更新一次最新的情况
	 */
	private static final long PERIOD_SECONDS = 30L;

	private final ScheduledThreadPoolExecutor peerConnectExecutor;

	private final Set<HashDigest> localLedgerCache = new HashSet<>();

	private final Lock ledgerHashLock = new ReentrantLock();

	private Map<NetworkAddress, PeerBlockchainServiceFactory> peerBlockchainServiceFactories = new ConcurrentHashMap<>();

	private Map<HashDigest, PeerBlockchainServiceFactory> latestPeerServiceFactories = new ConcurrentHashMap<>(16);

	private Set<NetworkAddress> peerAddresses = new HashSet<>();

	private volatile PeerServiceFactory mostLedgerPeerServiceFactory;

	private volatile AsymmetricKeypair gateWayKeyPair;

	private volatile List<String> peerProviders;

	private volatile EventListener eventListener;

	public PeerConnectionManager() {
		peerConnectExecutor = scheduledThreadPoolExecutor();
		executorStart();
	}

	@Override
	public Set<NetworkAddress> getPeerAddresses() {
		return peerAddresses;
	}

	@Override
	public boolean isConnected() {
		return !peerBlockchainServiceFactories.isEmpty();
	}

	@Override
	public synchronized void connect(NetworkAddress peerAddress, AsymmetricKeypair defaultKeyPair, List<String> peerProviders) {
		if (peerAddresses.contains(peerAddress)) {
			return;
		}
		// 连接成功的话，更新账本
		ledgerHashLock.lock();
		try {
			addPeerAddress(peerAddress);
			setGateWayKeyPair(defaultKeyPair);
			setPeerProviders(peerProviders);

			PeerBlockchainServiceFactory peerServiceFactory = PeerBlockchainServiceFactory.connect(defaultKeyPair, peerAddress, peerProviders);
			if (peerServiceFactory != null) {
				LOGGER.info("Connect peer {} success !!!", peerAddress);
				// 连接成功
				if (mostLedgerPeerServiceFactory == null) {
					// 默认设置为第一个连接成功的，后续更新需要等待定时任务处理
					mostLedgerPeerServiceFactory = new PeerServiceFactory(peerAddress, peerServiceFactory);
					LOGGER.info("Most ledgers remote update to {}", peerAddress);
				}
				peerBlockchainServiceFactories.put(peerAddress, peerServiceFactory);
				updateLedgerCache();
			}
		} catch (Exception e) {
			LOGGER.error("Connect peer {} fail !!!", peerAddress);
		} finally {
			// 连接成功的话，更新账本
			ledgerHashLock.unlock();
		}
	}

	@Override
	public void monitorAndReconnect() {
		if (getPeerAddresses().isEmpty()) {
			throw new IllegalArgumentException("Peer addresses must be init first !!!");
		}
		/**
		 * 1、首先判断是否之前连接成功过，若未成功则重连，走auth逻辑
		 * 2、若成功，则判断对端节点的账本与当前账本是否一致，有新增的情况下重连
		 */
		ledgerHashLock.lock();
		try {
			if (isConnected()) {
				LOGGER.info("----------- Start to load ledgers -----------");
				// 已连接成功，判断账本信息
				PeerServiceFactory serviceFactory = mostLedgerPeerServiceFactory;
				if (serviceFactory == null) {
					// 等待被更新
					return;
				}
				PeerBlockchainService queryService = serviceFactory.serviceFactory.getBlockchainService();
				NetworkAddress peerAddress = serviceFactory.peerAddress;

				HashDigest[] peerLedgerHashs = queryService.getLedgerHashsDirect();
				LOGGER.info("Most peer {} load ledger's size = {}", peerAddress, peerLedgerHashs.length);
				if (peerLedgerHashs.length > 0) {
					boolean haveNewLedger = false;
					for (HashDigest hash : peerLedgerHashs) {
						if (!localLedgerCache.contains(hash)) {
							haveNewLedger = true;
							break;
						}
					}
					if (haveNewLedger) {
						LOGGER.info("New ledger have been found, I will reconnect {} now !!!", peerAddress);
						// 有新账本的情况下重连，并更新本地账本
						try {
							PeerBlockchainServiceFactory peerServiceFactory = PeerBlockchainServiceFactory.connect(
									gateWayKeyPair, peerAddress, peerProviders);
							if (peerServiceFactory != null) {
								peerBlockchainServiceFactories.put(peerAddress, peerServiceFactory);
								localLedgerCache.addAll(Arrays.asList(peerLedgerHashs));
								mostLedgerPeerServiceFactory = new PeerServiceFactory(peerAddress, peerServiceFactory);
								LOGGER.info("Most ledgers remote update to {}", mostLedgerPeerServiceFactory.peerAddress);
							} else {
								LOGGER.error("Peer connect fail {}", peerAddress);
							}
						} catch (Exception e) {
							LOGGER.error(String.format("Peer connect fail %s", peerAddress), e);
						}
					}
				}
				LOGGER.info("----------- Load ledgers complete -----------");
			}
		} finally {
			ledgerHashLock.unlock();
		}
	}

	@Override
	public void close() {
		for (Map.Entry<NetworkAddress, PeerBlockchainServiceFactory> entry : peerBlockchainServiceFactories.entrySet()) {
			PeerBlockchainServiceFactory serviceFactory = entry.getValue();
			if (serviceFactory != null) {
				serviceFactory.close();
			}
		}
		peerBlockchainServiceFactories.clear();
	}

	@Override
	public BlockchainQueryService getQueryService() {
		// 查询选择最新的连接Factory
		PeerServiceFactory serviceFactory = this.mostLedgerPeerServiceFactory;
		if (serviceFactory == null) {
			throw new IllegalStateException("Peer connection was closed!");
		}
		return serviceFactory.serviceFactory.getBlockchainService();
	}

	@Override
	public BlockchainQueryService getQueryService(HashDigest ledgerHash) {
		PeerBlockchainServiceFactory serviceFactory = latestPeerServiceFactories.get(ledgerHash);
		if (serviceFactory == null) {
			return getQueryService();
		}
		return serviceFactory.getBlockchainService();
	}

	@Override
	public TransactionService getTransactionService() {
		// 交易始终使用第一个连接成功的即可
		PeerServiceFactory peerServiceFactory = mostLedgerPeerServiceFactory;
		if (peerServiceFactory == null) {
			throw new IllegalStateException("Peer connection was closed!");
		}
		PeerBlockchainServiceFactory serviceFactory = peerServiceFactory.serviceFactory;
		return serviceFactory.getTransactionService();
	}

	@PreDestroy
	private void destroy() {
		close();
	}

	public void addPeerAddress(NetworkAddress peerAddress) {
		this.peerAddresses.add(peerAddress);
	}

	public void setGateWayKeyPair(AsymmetricKeypair gateWayKeyPair) {
		this.gateWayKeyPair = gateWayKeyPair;
	}

	public void setPeerProviders(List<String> peerProviders) {
		this.peerProviders = peerProviders;
	}

	@Override
	public EventListener getEventListener() {
		if (eventListener == null) {
			eventListener = new PullEventListener(getQueryService());
			eventListener.start();
		}
		return eventListener;
	}

	/**
	 * 更新本地账本缓存
	 */
	private void updateLedgerCache() {
		if (isConnected()) {
			HashDigest[] peerLedgerHashs = getQueryService().getLedgerHashs();
			if (peerLedgerHashs != null && peerLedgerHashs.length > 0) {
				localLedgerCache.addAll(Arrays.asList(peerLedgerHashs));
			}
		}
	}

	/**
	 * 创建定时线程池
	 * @return
	 */
	private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor() {
		ThreadFactory threadFactory = new ThreadFactoryBuilder()
				.setNameFormat("peer-connect-%d").build();
		return new ScheduledThreadPoolExecutor(1,
				threadFactory,
				new ThreadPoolExecutor.AbortPolicy());
	}

	private void executorStart() {
		// 定时任务处理线程
		peerConnectExecutor.scheduleAtFixedRate(new PeerConnectRunner(), 0, PERIOD_SECONDS, TimeUnit.SECONDS);
	}


	private class PeerServiceFactory {

		private NetworkAddress peerAddress;

		private PeerBlockchainServiceFactory serviceFactory;

		PeerServiceFactory(NetworkAddress peerAddress, PeerBlockchainServiceFactory serviceFactory) {
			this.peerAddress = peerAddress;
			this.serviceFactory = serviceFactory;
		}
	}

	private class PeerConnectRunner implements Runnable {

		@Override
		public void run() {
			// 包括几部分工作
			// 1、重连没有连接成功的Peer；
			// 2、从已经连接成功的Peer节点获取账本数量和最新的区块高度
			// 3、根据目前的情况更新缓存
			ledgerHashLock.lock();
			try {
				reconnect();
				// 更新账本数量最多的节点连接
				HashDigest[] ledgerHashs = updateMostLedgerPeerServiceFactory();
				if (ledgerHashs != null) {
					LOGGER.info("Most ledgers remote update to {}", mostLedgerPeerServiceFactory.peerAddress);
					// 更新每个账本对应获取最高区块的缓存
					updateLatestPeerServiceFactories(ledgerHashs);
				}
			} catch (Exception e) {
				LOGGER.error("Peer Connect Task Error !!!", e);
			} finally {
				ledgerHashLock.unlock();
			}
		}

		/**
		 * 更新可获取最新区块的连接工厂
		 *
		 * @param ledgerHashs
		 *             账本列表
		 */
		private void updateLatestPeerServiceFactories(HashDigest[] ledgerHashs) {
			Map<HashDigest, PeerBlockchainServiceFactory> blockHeightServiceFactories = new HashMap<>();
			for (HashDigest ledgerHash : ledgerHashs) {
				long blockHeight = -1L;
				PeerBlockchainServiceFactory serviceFactory = latestPeerServiceFactories.get(ledgerHash);
				try {
					if (serviceFactory != null) {
						blockHeight = serviceFactory.getBlockchainService()
								.getLedger(ledgerHash).getLatestBlockHeight();
						blockHeightServiceFactories.put(ledgerHash, serviceFactory);
					}
				} catch (Exception e) {
					latestPeerServiceFactories.remove(ledgerHash);
					serviceFactory = null;
					LOGGER.error("Peer get latest block height fail !!!", e);
				}

				// 查询其他所有节点对应的区块高度的情况
				NetworkAddress defaultPeerAddress = null, latestPeerAddress = null;
				Map<NetworkAddress, PeerBlockchainServiceFactory> tmpEntries = new ConcurrentHashMap<>();
				for (Map.Entry<NetworkAddress, PeerBlockchainServiceFactory> entry : peerBlockchainServiceFactories.entrySet()) {
					PeerBlockchainServiceFactory sf = entry.getValue();
					if (sf != serviceFactory) {
						try {
							long latestBlockHeight = sf.getBlockchainService().getLedger(ledgerHash).getLatestBlockHeight();
							if (latestBlockHeight > blockHeight) {
								latestPeerAddress = entry.getKey();
								blockHeightServiceFactories.put(ledgerHash, sf);
							}
							blockHeight = Math.max(latestBlockHeight, blockHeight);
						} catch (Exception e) {
							// 需要判断是否具有当前账本，有的话，进行重连，没有的话就算了
							PeerBlockchainService blockchainService = sf.getBlockchainService();
							boolean isNeedReconnect = false;
							ledgerHashs = blockchainService.getLedgerHashsDirect();
							if (ledgerHashs != null) {
								for (HashDigest h : ledgerHashs) {
									if (h.equals(ledgerHash)) {
										// 确实存在对应的账本，则重连
										isNeedReconnect = true;
									}
								}
							}
							if (isNeedReconnect) {
								// 需要重连的话打印错误信息
								LOGGER.error(String.format("Peer[%s] get ledger[%s]'s latest block height fail !!!",
										entry.getKey(), ledgerHash.toBase58()), e);
								// 此错误是由于对端的节点没有重连导致，需要进行重连操作
								NetworkAddress peerAddress = entry.getKey();
								try {
									PeerBlockchainServiceFactory peerServiceFactory = PeerBlockchainServiceFactory.connect(
											gateWayKeyPair, peerAddress, peerProviders);
									if (peerServiceFactory != null) {
										tmpEntries.put(peerAddress, peerServiceFactory);
									}
								} catch (Exception ee) {
									LOGGER.error(String.format("Peer[%s] reconnect fail !!!",
											entry.getKey()), e);
								}
							}
						}
					} else {
						defaultPeerAddress = entry.getKey();
					}
				}
				if (!tmpEntries.isEmpty()) {
					peerBlockchainServiceFactories.putAll(tmpEntries);
				}
				LOGGER.info("Ledger[{}]'s master remote update to {}", ledgerHash.toBase58(),
						latestPeerAddress == null ? defaultPeerAddress : latestPeerAddress);
			}
			// 更新结果集
			latestPeerServiceFactories.putAll(blockHeightServiceFactories);
		}

		/**
		 * 之前未连接成功的Peer节点进行重连操作
		 *
		 */
		private void reconnect() {
			for (NetworkAddress peerAddress : peerAddresses) {
				if (!peerBlockchainServiceFactories.containsKey(peerAddress)) {
					// 重连指定节点
					try {
						PeerBlockchainServiceFactory peerServiceFactory = PeerBlockchainServiceFactory.connect(gateWayKeyPair, peerAddress, peerProviders);
						if (peerServiceFactory != null) {
							peerBlockchainServiceFactories.put(peerAddress, peerServiceFactory);
						}
					} catch (Exception e) {
						LOGGER.error(String.format("Reconnect %s fail !!!", peerAddress), e);
					}
				}
			}
		}

		private HashDigest[] updateMostLedgerPeerServiceFactory() {
			int ledgerSize = -1;
			if (mostLedgerPeerServiceFactory == null) {
				return null;
			}
			HashDigest[] ledgerHashs = null;
			PeerBlockchainService blockchainService = mostLedgerPeerServiceFactory.serviceFactory.getBlockchainService();
			try {
				ledgerHashs = blockchainService.getLedgerHashsDirect();
				if (ledgerHashs != null) {
					ledgerSize = ledgerHashs.length;
					for (HashDigest h : ledgerHashs) {
						LOGGER.debug("Most peer[{}] get ledger direct [{}]", mostLedgerPeerServiceFactory.peerAddress, h.toBase58());
					}
				}
			} catch (Exception e) {
				// 连接失败的情况下清除该连接
				LOGGER.error(String.format("Connect %s fail !!!", mostLedgerPeerServiceFactory.peerAddress), e);
				peerBlockchainServiceFactories.remove(mostLedgerPeerServiceFactory.peerAddress);
				mostLedgerPeerServiceFactory = null;
				blockchainService = null;
			}
			PeerServiceFactory tempMostLedgerPeerServiceFactory = mostLedgerPeerServiceFactory;

			// 遍历，获取对应端的账本数量及最新的区块高度
			for (Map.Entry<NetworkAddress, PeerBlockchainServiceFactory> entry : peerBlockchainServiceFactories.entrySet()) {
				PeerBlockchainService loopBlockchainService = entry.getValue().getBlockchainService();
				if (loopBlockchainService != blockchainService) {
					// 处理账本数量
					try {
						HashDigest[] tempLedgerHashs = loopBlockchainService.getLedgerHashsDirect();
						if (tempLedgerHashs != null) {
							for (HashDigest h : tempLedgerHashs) {
								LOGGER.debug("Temp peer[{}] get ledger direct [{}]", entry.getKey(), h.toBase58());
							}
							if (tempLedgerHashs.length > ledgerSize) {
								tempMostLedgerPeerServiceFactory = new PeerServiceFactory(entry.getKey(),entry.getValue());
								ledgerHashs = tempLedgerHashs;
							}
						}
					} catch (Exception e) {
						LOGGER.error(String.format("%s get ledger hash fail !!!", entry.getKey()), e);
					}
				}
			}
			// 更新mostLedgerPeerServiceFactory
			mostLedgerPeerServiceFactory = tempMostLedgerPeerServiceFactory;
			return ledgerHashs;
		}
	}
}
