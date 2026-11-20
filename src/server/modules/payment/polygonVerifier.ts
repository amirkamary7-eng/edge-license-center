import { PAYMENT_NETWORK } from '../../../shared/constants';

export interface EvmLogEntry {
  address: string;
  topics: string[];
  data: string;
}

export interface EvmTransactionReceipt {
  transactionHash: string;
  status: string; // '0x1' = success, '0x0' = reverted
  blockNumber: string; // hex string
  from: string;
  to: string | null;
  logs: EvmLogEntry[];
}

export interface ParsedUsdcTransfer {
  contractAddress: string;
  fromAddress: string;
  toAddress: string;
  amountUsdcMicro: bigint;
}

export interface PolygonVerificationResult {
  valid: boolean;
  reason?:
    | 'INVALID_TX_HASH'
    | 'WRONG_CHAIN_ID'
    | 'RECEIPT_NOT_FOUND'
    | 'RECEIPT_TX_HASH_MISMATCH'
    | 'TX_REVERTED'
    | 'INSUFFICIENT_CONFIRMATIONS'
    | 'BLOCK_TIMESTAMP_MISSING'
    | 'TX_PREDATES_ORDER'
    | 'TX_AFTER_ORDER_EXPIRY'
    | 'NO_MATCHING_NATIVE_USDC_TRANSFER'
    | 'SENDER_WALLET_MISMATCH'
    | 'UNDERPAID_AMOUNT'
    | 'AMOUNT_MISMATCH_CROSS_ORDER';
  txHash: string;
  chainId?: number;
  blockNumber?: number;
  blockTimestamp?: number;
  confirmations?: number;
  senderAddress?: string;
  receiverAddress?: string;
  matchedAmountUsdcMicro?: number;
}

export interface PolygonRpcProvider {
  getChainId(): Promise<number>;
  getTransactionReceipt(txHash: string): Promise<EvmTransactionReceipt | null>;
  getLatestBlockNumber(): Promise<number>;
  getBlockTimestamp(blockNumberHex: string): Promise<number | null>;
}

const TX_HASH_REGEX = /^0x[a-fA-F0-9]{64}$/;
const EVM_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

export function isValidPolygonTxHash(txHash: string): boolean {
  return TX_HASH_REGEX.test(txHash.trim());
}

export function isValidEvmAddress(address: string): boolean {
  return EVM_ADDRESS_REGEX.test(address.trim());
}

export function normalizeTxHash(txHash: string): string {
  return txHash.trim().toLowerCase();
}

export function normalizeEvmAddress(address: string): string {
  return address.trim().toLowerCase();
}

function decodeTopicAddress(topic: string): string {
  const clean = topic.toLowerCase().replace(/^0x/, '');
  if (clean.length !== 64) {
    throw new Error('INVALID_EVM_ADDRESS_TOPIC');
  }
  return `0x${clean.slice(24)}`;
}

/**
 * Extracts all official Polygon PoS Native USDC ERC-20 Transfer logs from a receipt.
 * Strictly ignores bridged USDC.e or spoofed ERC-20 contracts by checking exact contract address.
 */
export function extractNativeUsdcTransfers(
  receipt: EvmTransactionReceipt,
  officialUsdcContract: string = PAYMENT_NETWORK.usdcContractAddress
): ParsedUsdcTransfer[] {
  const expectedContract = officialUsdcContract.toLowerCase();
  const transferTopic = PAYMENT_NETWORK.erc20TransferTopic.toLowerCase();
  const transfers: ParsedUsdcTransfer[] = [];

  for (const log of receipt.logs ?? []) {
    if (!log.address || log.address.toLowerCase() !== expectedContract) {
      continue;
    }
    if (!Array.isArray(log.topics) || log.topics.length < 3) {
      continue;
    }
    if (log.topics[0].toLowerCase() !== transferTopic) {
      continue;
    }
    try {
      const fromAddress = decodeTopicAddress(log.topics[1]);
      const toAddress = decodeTopicAddress(log.topics[2]);
      const amountUsdcMicro = BigInt(log.data);
      transfers.push({
        contractAddress: log.address.toLowerCase(),
        fromAddress,
        toAddress,
        amountUsdcMicro,
      });
    } catch {
      continue;
    }
  }

  return transfers;
}

/**
 * Deterministic verification of a Polygon PoS transaction receipt against:
 * - Chain ID === 137 (Polygon PoS)
 * - Exact receipt.transactionHash === txHash
 * - Receipt status === 0x1
 * - Block confirmations >= minConfirmations
 * - Block timestamp within [orderCreatedEpoch - 60s, orderExpiresEpoch] (blocks stale/historical Tx replay)
 * - Official Native USDC contract Transfer log to official destination treasury wallet
 * - Exact payable micro-USDC match (anti-front-running unique micro-offset) or >= expected when exactMatch is false
 * - Optional expected sender wallet match
 */
export function verifyPolygonUsdcReceipt(params: {
  txHash: string;
  receipt: EvmTransactionReceipt | null;
  latestBlockNumber: number;
  expectedAmountUsdcMicro: number;
  chainId?: number;
  blockTimestamp?: number | null;
  orderCreatedEpoch?: number;
  orderExpiresEpoch?: number;
  expectedSenderWallet?: string | null;
  requireExactAmount?: boolean;
  minConfirmations?: number;
  expectedContract?: string;
  expectedDestinationWallet?: string;
}): PolygonVerificationResult {
  const normalizedHash = normalizeTxHash(params.txHash);
  if (!isValidPolygonTxHash(normalizedHash)) {
    return { valid: false, reason: 'INVALID_TX_HASH', txHash: normalizedHash };
  }

  if (params.chainId !== undefined && params.chainId !== PAYMENT_NETWORK.chainId) {
    return {
      valid: false,
      reason: 'WRONG_CHAIN_ID',
      txHash: normalizedHash,
      chainId: params.chainId,
    };
  }

  if (!params.receipt) {
    return { valid: false, reason: 'RECEIPT_NOT_FOUND', txHash: normalizedHash };
  }

  if (
    !params.receipt.transactionHash ||
    normalizeTxHash(params.receipt.transactionHash) !== normalizedHash
  ) {
    return { valid: false, reason: 'RECEIPT_TX_HASH_MISMATCH', txHash: normalizedHash };
  }

  if (params.receipt.status?.toLowerCase() !== '0x1') {
    return { valid: false, reason: 'TX_REVERTED', txHash: normalizedHash };
  }

  const blockNumber = Number.parseInt(params.receipt.blockNumber, 16);
  const confirmations = Math.max(0, params.latestBlockNumber - blockNumber + 1);
  const minConfirmations = params.minConfirmations ?? PAYMENT_NETWORK.minConfirmations;

  if (!Number.isFinite(blockNumber) || confirmations < minConfirmations) {
    return {
      valid: false,
      reason: 'INSUFFICIENT_CONFIRMATIONS',
      txHash: normalizedHash,
      blockNumber: Number.isFinite(blockNumber) ? blockNumber : undefined,
      confirmations,
    };
  }

  // Enforce order temporal bounds when provided (prevents claiming old historical USDC transfers)
  if (params.orderCreatedEpoch !== undefined || params.orderExpiresEpoch !== undefined) {
    if (params.blockTimestamp === null || params.blockTimestamp === undefined) {
      return {
        valid: false,
        reason: 'BLOCK_TIMESTAMP_MISSING',
        txHash: normalizedHash,
        blockNumber,
        confirmations,
      };
    }
    if (
      params.orderCreatedEpoch !== undefined &&
      params.blockTimestamp < params.orderCreatedEpoch - 15
    ) {
      return {
        valid: false,
        reason: 'TX_PREDATES_ORDER',
        txHash: normalizedHash,
        blockNumber,
        blockTimestamp: params.blockTimestamp,
        confirmations,
      };
    }
    if (
      params.orderExpiresEpoch !== undefined &&
      params.blockTimestamp > params.orderExpiresEpoch
    ) {
      return {
        valid: false,
        reason: 'TX_AFTER_ORDER_EXPIRY',
        txHash: normalizedHash,
        blockNumber,
        blockTimestamp: params.blockTimestamp,
        confirmations,
      };
    }
  }

  const expectedWallet = (
    params.expectedDestinationWallet ?? PAYMENT_NETWORK.destinationWalletAddress
  ).toLowerCase();
  const transfers = extractNativeUsdcTransfers(
    params.receipt,
    params.expectedContract ?? PAYMENT_NETWORK.usdcContractAddress
  );

  const matchingToTreasury = transfers.filter((t) => t.toAddress === expectedWallet);
  if (matchingToTreasury.length === 0) {
    return {
      valid: false,
      reason: 'NO_MATCHING_NATIVE_USDC_TRANSFER',
      txHash: normalizedHash,
      blockNumber,
      blockTimestamp: params.blockTimestamp ?? undefined,
      confirmations,
    };
  }

  let eligibleTransfers = matchingToTreasury;
  if (params.expectedSenderWallet) {
    const normalizedExpectedSender = normalizeEvmAddress(params.expectedSenderWallet);
    eligibleTransfers = matchingToTreasury.filter(
      (t) => t.fromAddress === normalizedExpectedSender
    );
    if (eligibleTransfers.length === 0) {
      return {
        valid: false,
        reason: 'SENDER_WALLET_MISMATCH',
        txHash: normalizedHash,
        blockNumber,
        blockTimestamp: params.blockTimestamp ?? undefined,
        confirmations,
        senderAddress: matchingToTreasury[0].fromAddress,
        receiverAddress: expectedWallet,
      };
    }
  }

  let totalMicro = 0n;
  for (const t of eligibleTransfers) {
    totalMicro += t.amountUsdcMicro;
  }

  const expectedMicroBig = BigInt(params.expectedAmountUsdcMicro);
  const safeMatchedMicro =
    totalMicro > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(totalMicro);

  if (totalMicro < expectedMicroBig) {
    return {
      valid: false,
      reason: 'UNDERPAID_AMOUNT',
      txHash: normalizedHash,
      blockNumber,
      blockTimestamp: params.blockTimestamp ?? undefined,
      confirmations,
      senderAddress: eligibleTransfers[0].fromAddress,
      receiverAddress: expectedWallet,
      matchedAmountUsdcMicro: safeMatchedMicro,
    };
  }

  if (params.requireExactAmount && totalMicro !== expectedMicroBig) {
    return {
      valid: false,
      reason: 'AMOUNT_MISMATCH_CROSS_ORDER',
      txHash: normalizedHash,
      blockNumber,
      blockTimestamp: params.blockTimestamp ?? undefined,
      confirmations,
      senderAddress: eligibleTransfers[0].fromAddress,
      receiverAddress: expectedWallet,
      matchedAmountUsdcMicro: safeMatchedMicro,
    };
  }

  return {
    valid: true,
    txHash: normalizedHash,
    chainId: params.chainId ?? PAYMENT_NETWORK.chainId,
    blockNumber,
    blockTimestamp: params.blockTimestamp ?? undefined,
    confirmations,
    senderAddress: eligibleTransfers[0].fromAddress,
    receiverAddress: expectedWallet,
    matchedAmountUsdcMicro: safeMatchedMicro,
  };
}

/**
 * Production-hardened JSON-RPC client for Polygon PoS with AbortController timeouts
 * and injectable fetch transport for isolated unit/integration tests.
 */
export class PolygonRpcClient implements PolygonRpcProvider {
  constructor(
    private readonly rpcUrl: string,
    private readonly options?: {
      timeoutMs?: number;
      fetchImpl?: typeof fetch;
    }
  ) {}

  private async rpcCall<T>(method: string, params: unknown[]): Promise<T> {
    const controller = new AbortController();
    const timeoutMs = this.options?.timeoutMs ?? 10000;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const fetcher = this.options?.fetchImpl ?? fetch;

    try {
      const res = await fetcher(this.rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`POLYGON_RPC_HTTP_${res.status}`);
      }
      const json = (await res.json()) as { result?: T; error?: { message: string } };
      if (json.error) {
        throw new Error(`POLYGON_RPC_ERROR: ${json.error.message}`);
      }
      return json.result as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async getChainId(): Promise<number> {
    const hex = await this.rpcCall<string>('eth_chainId', []);
    return Number.parseInt(hex, 16);
  }

  async getTransactionReceipt(txHash: string): Promise<EvmTransactionReceipt | null> {
    return this.rpcCall<EvmTransactionReceipt | null>('eth_getTransactionReceipt', [txHash]);
  }

  async getLatestBlockNumber(): Promise<number> {
    const hex = await this.rpcCall<string>('eth_blockNumber', []);
    return Number.parseInt(hex, 16);
  }

  async getBlockTimestamp(blockNumberHex: string): Promise<number | null> {
    const block = await this.rpcCall<{ timestamp?: string } | null>('eth_getBlockByNumber', [
      blockNumberHex,
      false,
    ]);
    if (!block?.timestamp) return null;
    const parsed = Number.parseInt(block.timestamp, 16);
    return Number.isFinite(parsed) ? parsed : null;
  }
}
