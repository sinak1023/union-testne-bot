const fs = require('fs');
const path = require('path');
const { ethers, JsonRpcProvider } = require('ethers');
const axios = require('axios');
const moment = require('moment-timezone');
const readline = require('readline');
const TelegramBot = require('node-telegram-bot-api');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
require('dotenv').config();

const colors = {
  reset: "\x1b[0m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  white: "\x1b[37m",
  bold: "\x1b[1m"
};

const logger = {
  info: (msg) => console.log(`${colors.green}[✓] ${msg}${colors.reset}`),
  warn: (msg) => console.log(`${colors.yellow}[⚠] ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}[✗] ${msg}${colors.reset}`),
  success: (msg) => console.log(`${colors.green}[✅] ${msg}${colors.reset}`),
  loading: (msg) => console.log(`${colors.cyan}[⟳] ${msg}${colors.reset}`),
  step: (msg) => console.log(`${colors.white}[➤] ${msg}${colors.reset}`),
  banner: () => {
    console.log(`${colors.cyan}${colors.bold}`);
    console.log(`---------------------------------------------`);
    console.log(`  Union Testnet Auto Bot - Kachal God Mod    `);
    console.log(`---------------------------------------------${colors.reset}`);
    console.log();
  }
};

const UCS03_ABI = [
  {
    inputs: [
      { internalType: 'uint32', name: 'channelId', type: 'uint32' },
      { internalType: 'uint64', name: 'timeoutHeight', type: 'uint64' },
      { internalType: 'uint64', name: 'timeoutTimestamp', type: 'uint64' },
      { internalType: 'bytes32', name: 'salt', type: 'bytes32' },
      {
        components: [
          { internalType: 'uint8', name: 'version', type: 'uint8' },
          { internalType: 'uint8', name: 'opcode', type: 'uint8' },
          { internalType: 'bytes', name: 'operand', type: 'bytes' },
        ],
        internalType: 'struct Instruction',
        name: 'instruction',
        type: 'tuple',
      },
    ],
    name: 'send',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
];

const USDC_ABI = [
  {
    constant: true,
    inputs: [{ name: 'account', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', type: 'uint256' }],
    type: 'function',
    stateMutability: 'view',
  },
  {
    constant: true,
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    name: 'allowance',
    outputs: [{ name: '', type: 'uint256' }],
    type: 'function',
    stateMutability: 'view',
  },
  {
    constant: false,
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'value', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ name: '', type: 'bool' }],
    type: 'function',
    stateMutability: 'nonpayable',
  },
  {
    constant: false,
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
    ],
    name: 'transfer',
    outputs: [{ name: '', type: 'bool' }],
    type: 'function',
    stateMutability: 'nonpayable',
  },
];

const contractAddress = '0x5FbE74A283f7954f10AA04C2eDf55578811aeb03';
const USDC_ADDRESS = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238';
const graphqlEndpoint = 'https://graphql.union.build/v1/graphql';
const baseExplorerUrl = 'https://sepolia.etherscan.io';
const unionUrl = 'https://app.union.build/explorer';

const rpcProviders = [new JsonRpcProvider('https://eth-sepolia.public.blastapi.io')];
let currentRpcProviderIndex = 0;

function provider() {
  return rpcProviders[currentRpcProviderIndex];
}

function rotateRpcProvider() {
  currentRpcProviderIndex = (currentRpcProviderIndex + 1) % rpcProviders.length;
  return provider();
}

let proxies = [];
try {
  const proxiesContent = fs.readFileSync('proxies.txt', 'utf8');
  proxies = proxiesContent.split('\n').map(proxy => proxy.trim()).filter(proxy => proxy);
} catch (err) {
  logger.warn(`No proxies.txt found or error reading: ${err.message}. Running without proxies.`);
}

function getAxiosConfig() {
  if (proxies.length > 0) {
    const proxy = proxies[Math.floor(Math.random() * proxies.length)];
    return {
      proxy: {
        protocol: 'http',
        host: proxy.split('@')[1]?.split(':')[0] || proxy.split('://')[1].split(':')[0],
        port: parseInt(proxy.split('@')[1]?.split(':')[1] || proxy.split('://')[1].split(':')[1]),
        auth: proxy.includes('@') ? {
          username: proxy.split('://')[1].split('@')[0].split(':')[0],
          password: proxy.split('://')[1].split('@')[0].split(':')[1]
        } : undefined
      }
    };
  }
  return {};
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function askQuestion(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

const explorer = {
  tx: (txHash) => `${baseExplorerUrl}/tx/${txHash}`,
  address: (address) => `${baseExplorerUrl}/address/${address}`,
};

const union = {
  tx: (txHash) => `${unionUrl}/transfers/${txHash}`,
};

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function timelog() {
  return moment().tz('Asia/Jakarta').format('HH:mm:ss | DD-MM-YYYY');
}

function header() {
  process.stdout.write('\x1Bc');
  logger.banner();
}

const WALLET_FILE = path.join(__dirname, 'wallets.json');

function loadWallets() {
  try {
    if (fs.existsSync(WALLET_FILE)) {
      return JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
    }
    return [];
  } catch (err) {
    logger.error(`Error loading wallets: ${err.message}`);
    return [];
  }
}

function saveWallets(wallets) {
  try {
    fs.writeFileSync(WALLET_FILE, JSON.stringify(wallets, null, 2));
    logger.success('Wallets saved to wallets.json');
  } catch (err) {
    logger.error(`Error saving wallets: ${err.message}`);
  }
}

async function pollPacketHash(txHash, retries = 50, intervalMs = 5000) {
  const headers = {
    accept: 'application/graphql-response+json, application/json',
    'accept-encoding': 'gzip, deflate, br, zstd',
    'accept-language': 'en-US,en;q=0.9,id;q=0.8',
    'content-type': 'application/json',
    origin: 'https://app-union.build',
    referer: 'https://app.union.build/',
    'user-agent': 'Mozilla/5.0',
  };
  const data = {
    query: `
      query ($submission_tx_hash: String!) {
        v2_transfers(args: {p_transaction_hash: $submission_tx_hash}) {
          packet_hash
        }
      }
    `,
    variables: {
      submission_tx_hash: txHash.startsWith('0x') ? txHash : `0x${txHash}`,
    },
  };

  for (let i = 0; i < retries; i++) {
    try {
      const res = await axios.post(graphqlEndpoint, data, { headers, ...getAxiosConfig() });
      const result = res.data?.data?.v2_transfers;
      if (result && result.length > 0 && result[0].packet_hash) {
        return { success: true, packetHash: result[0].packet_hash };
      }
    } catch (e) {
      return { success: false, message: `Packet error: ${e.message}` };
    }
    await delay(intervalMs);
  }
  return { success: false, message: `No packet hash found after ${retries} retries.` };
}

async function checkBalanceAndApprove(wallet, usdcAddress, spenderAddress, amountUSDC, numTransactions) {
  const logs = [];
  const usdcContract = new ethers.Contract(usdcAddress, USDC_ABI, wallet);
  const balance = await usdcContract.balanceOf(wallet.address);
  const requiredBalance = ethers.parseUnits(amountUSDC.toString(), 6) * BigInt(numTransactions);
  if (balance < requiredBalance) {
    const msg = `${wallet.address} does not have enough USDC. Required: ${ethers.formatUnits(requiredBalance, 6)} USDC, Available: ${ethers.formatUnits(balance, 6)} USDC`;
    logs.push({ type: 'error', message: msg });
    return { success: false, logs };
  }

  const allowance = await usdcContract.allowance(wallet.address, spenderAddress);
  if (allowance < requiredBalance) {
    const msg = `USDC allowance insufficient. Sending approve transaction...`;
    logs.push({ type: 'loading', message: msg });
    const approveAmount = ethers.MaxUint256;
    try {
      const tx = await usdcContract.approve(spenderAddress, approveAmount);
      const receipt = await tx.wait();
      const successMsg = `Approve confirmed: ${explorer.tx(receipt.hash)}`;
      logs.push({ type: 'success', message: successMsg });
      await delay(3000);
    } catch (err) {
      const errMsg = `Approve failed: ${err.message}`;
      logs.push({ type: 'error', message: errMsg });
      return { success: false, logs };
    }
  }
  return { success: true, logs };
}

async function sendFromWallet(walletInfo, maxTransaction, destination, minPercent, maxPercent, delaySeconds) {
  const logs = [];
  const wallet = new ethers.Wallet(walletInfo.privatekey, provider());
  let recipientAddress, destinationName, channelId, operand;

  if (destination === 'babylon') {
    recipientAddress = walletInfo.babylonAddress;
    destinationName = 'Babylon';
    channelId = 7;
    if (!recipientAddress) {
      const msg = `Skipping wallet '${walletInfo.name || 'Unnamed'}': Missing babylonAddress.`;
      logs.push({ type: 'warn', message: msg });
      return { logs };
    }
  } else if (destination === 'holesky') {
    recipientAddress = wallet.address;
    destinationName = 'Holesky';
    channelId = 8;
  } else {
    const msg = `Invalid destination: ${destination}`;
    logs.push({ type: 'error', message: msg });
    return { logs };
  }

  const usdcContract = new ethers.Contract(USDC_ADDRESS, USDC_ABI, wallet);
  const balance = await usdcContract.balanceOf(wallet.address);
  const balanceUSDC = parseFloat(ethers.formatUnits(balance, 6));
  if (balanceUSDC <= 0) {
    const msg = `Wallet ${wallet.address} (${walletInfo.name || 'Unnamed'}) has no USDC balance.`;
    logs.push({ type: 'error', message: msg });
    return { logs };
  }

  const minAmount = balanceUSDC * (minPercent / 100);
  const maxAmount = balanceUSDC * (maxPercent / 100);
  const amountUSDC = Math.random() * (maxAmount - minAmount) + minAmount;
  const formattedAmount = parseFloat(amountUSDC.toFixed(6));

  const msg = `Sending ${maxTransaction} Transaction(s) of ${formattedAmount} USDC Sepolia to ${destinationName} from ${wallet.address} (${walletInfo.name || 'Unnamed'})`;
  logs.push({ type: 'loading', message: msg });

  const approvalResult = await checkBalanceAndApprove(wallet, USDC_ADDRESS, contractAddress, formattedAmount, maxTransaction);
  logs.push(...approvalResult.logs);
  if (!approvalResult.success) return { logs };

  const contract = new ethers.Contract(contractAddress, UCS03_ABI, wallet);
  const senderHex = wallet.address.slice(2).toLowerCase();
  const recipientHex = destination === 'babylon' ? Buffer.from(recipientAddress, "utf8").toString("hex") : senderHex;
  const timeoutHeight = 0;

  const amountWei = ethers.parseUnits(formattedAmount.toString(), 6).toString(16).padStart(64, '0');

  if (destination === 'babylon') {
    operand = `0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000002710000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000002600000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000014${senderHex}000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a${recipientHex}0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000141c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000000000000000000000000000000000000000000000000000000000000000000004555344430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045553444300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e62626e317a7372763233616b6b6778646e77756c3732736674677632786a74356b68736e743377776a687030666668363833687a7035617135613068366e0000`;
  } else {
    operand = `0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000014${senderHex}0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014${senderHex}00000000000000000000000000000000000000000000000000000000000000000000000000000000000000141c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000000000000000000000000000000000000000000000000000000000000000000004555344430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045553444300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001457978bfe465ad9b1c0bf80f6c1539d300705ea50000000000000000000000000`;
  }

  for (let i = 1; i <= maxTransaction; i++) {
    const stepMsg = `${walletInfo.name || 'Unnamed'} | Transaction ${i}/${maxTransaction} (${formattedAmount} USDC)`;
    logs.push({ type: 'step', message: stepMsg });
    const now = BigInt(Date.now()) * 1_000_000n;
    const oneDayNs = 86_400_000_000_000n;
    const timeoutTimestamp = (now + oneDayNs).toString();
    const timestampNow = Math.floor(Date.now() / 1000);
    const salt = ethers.keccak256(ethers.solidityPacked(['address', 'uint256'], [wallet.address, timestampNow]));
    const instruction = {
      version: 0,
      opcode: 2,
      operand,
    };

    try {
      const tx = await contract.send(channelId, timeoutHeight, timeoutTimestamp, salt, instruction);
      await tx.wait(1);
      const successMsg = `${timelog()} | ${walletInfo.name || 'Unnamed'} | Transaction Confirmed: ${explorer.tx(tx.hash)}`;
      logs.push({ type: 'success', message: successMsg });
      const txHash = tx.hash.startsWith('0x') ? tx.hash : `0x${tx.hash}`;
      const packetResult = await pollPacketHash(txHash);
      if (packetResult.success) {
        const packetMsg = `${timelog()} | ${walletInfo.name || 'Unnamed'} | Packet Submitted: ${union.tx(packetResult.packetHash)}`;
        logs.push({ type: 'success', message: packetMsg });
      } else {
        logs.push({ type: packetResult.message.includes('No packet hash') ? 'warn' : 'error', message: packetResult.message });
      }
      logs.push({ type: 'info', message: '' });
    } catch (err) {
      const errMsg = `Failed for ${wallet.address}: ${err.message}`;
      logs.push({ type: 'error', message: errMsg });
      logs.push({ type: 'info', message: '' });
    }

    if (i < maxTransaction) {
      const delayMsg = `Waiting ${delaySeconds} seconds before next transaction...`;
      logs.push({ type: 'info', message: delayMsg });
      await delay(delaySeconds * 1000);
    }
  }

  return { logs };
}

async function getFaucetPrivateKey(isTelegram, selectedWalletName = null) {
  let faucetPrivateKey = '';
  if (!isTelegram) {
    try {
      const faucetContent = fs.readFileSync('faucet.txt', 'utf8');
      const faucetKeys = faucetContent.split('\n').map(key => key.trim()).filter(key => key);
      if (faucetKeys.length > 0) {
        faucetPrivateKey = faucetKeys[0];
      }
    } catch (err) {
      logger.warn(`Failed to read faucet.txt: ${err.message}. Falling back to wallets.json.`);
    }
  }

  if (!faucetPrivateKey || !faucetPrivateKey.startsWith('0x') || !/^(0x)[0-9a-fA-F]{64}$/.test(faucetPrivateKey)) {
    const wallets = loadWallets();
    if (wallets.length === 0) {
      return { success: false, message: `No valid wallets found in wallets.json.` };
    }

    let selectedWallet;
    if (selectedWalletName) {
      selectedWallet = wallets.find(w => w.name === selectedWalletName);
      if (!selectedWallet) {
        return { success: false, message: `Wallet '${selectedWalletName}' not found in wallets.json.` };
      }
    } else {
      selectedWallet = wallets.find(w => w.privatekey && w.privatekey.startsWith('0x') && /^(0x)[0-9a-fA-F]{64}$/.test(w.privatekey));
    }

    if (!selectedWallet) {
      return { success: false, message: `No valid faucet private key found in wallets.json.` };
    }

    faucetPrivateKey = selectedWallet.privatekey;
  }

  if (!faucetPrivateKey.startsWith('0x') || !/^(0x)[0-9a-fA-F]{64}$/.test(faucetPrivateKey)) {
    return { success: false, message: `Invalid faucet private key. Must start with '0x' and be a 64-character hexadecimal string.` };
  }

  return { success: true, faucetPrivateKey };
}

async function faucetTransferUSDC(faucetPrivateKeyOrWalletName, wallets, amountUSDC, delaySeconds, isTelegram = false, telegramBot = null, chatId = null) {
  const logs = [];
  const faucetKeyResult = await getFaucetPrivateKey(isTelegram, isTelegram ? faucetPrivateKeyOrWalletName : null);
  if (!faucetKeyResult.success) {
    logs.push({ type: 'error', message: faucetKeyResult.message });
    if (telegramBot && chatId) telegramBot.sendMessage(chatId, faucetKeyResult.message);
    return { logs };
  }

  const faucetPrivateKey = faucetKeyResult.faucetPrivateKey;
  const faucetWallet = new ethers.Wallet(faucetPrivateKey, provider());
  const usdcContract = new ethers.Contract(USDC_ADDRESS, USDC_ABI, faucetWallet);
  const msg = `Checking faucet wallet balance (${faucetWallet.address})...`;
  logs.push({ type: 'loading', message: msg });
  if (telegramBot && chatId) telegramBot.sendMessage(chatId, msg);
  const faucetBalance = await usdcContract.balanceOf(faucetWallet.address);
  const faucetBalanceUSDC = parseFloat(ethers.formatUnits(faucetBalance, 6));
  if (faucetBalanceUSDC < amountUSDC * wallets.length) {
    const errMsg = `Faucet wallet ${faucetWallet.address} has insufficient USDC. Required: ${amountUSDC * wallets.length} USDC, Available: ${faucetBalanceUSDC} USDC`;
    logs.push({ type: 'error', message: errMsg });
    if (telegramBot && chatId) telegramBot.sendMessage(chatId, errMsg);
    return { logs };
  }

  const formattedAmount = parseFloat(amountUSDC.toFixed(6));
  const amountWei = ethers.parseUnits(formattedAmount.toString(), 6);

  for (let i = 0; i < wallets.length; i++) {
    const walletInfo = wallets[i];
    if (!walletInfo.privatekey || !walletInfo.privatekey.startsWith('0x') || !/^(0x)[0-9a-fA-F]{64}$/.test(walletInfo.privatekey)) {
      const msg = `Skipping wallet '${walletInfo.name}': Invalid private key.`;
      logs.push({ type: 'warn', message: msg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, msg);
      continue;
    }

    let recipientWallet;
    try {
      recipientWallet = new ethers.Wallet(walletInfo.privatekey, provider());
    } catch (err) {
      const msg = `Skipping wallet '${walletInfo.name}': Failed to create wallet - ${err.message}`;
      logs.push({ type: 'warn', message: msg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, msg);
      continue;
    }

    const stepMsg = `Transferring ${formattedAmount} USDC to ${recipientWallet.address} (${walletInfo.name})`;
    logs.push({ type: 'step', message: stepMsg });
    if (telegramBot && chatId) telegramBot.sendMessage(chatId, stepMsg);
    try {
      const tx = await usdcContract.transfer(recipientWallet.address, amountWei);
      const receipt = await tx.wait();
      const successMsg = `${timelog()} | USDC Transfer Confirmed: ${explorer.tx(receipt.hash)}`;
      logs.push({ type: 'success', message: successMsg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, successMsg);
    } catch (err) {
      const errMsg = `USDC Transfer failed for ${recipientWallet.address}: ${err.message}`;
      logs.push({ type: 'error', message: errMsg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, errMsg);
    }

    if (i < wallets.length - 1) {
      const delayMsg = `Waiting ${delaySeconds} seconds before next transfer...`;
      logs.push({ type: 'info', message: delayMsg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, delayMsg);
      await delay(delaySeconds * 1000);
    }
  }

  return { logs };
}

async function faucetTransferETH(faucetPrivateKeyOrWalletName, wallets, amountETH, delaySeconds, isTelegram = false, telegramBot = null, chatId = null) {
  const logs = [];
  const faucetKeyResult = await getFaucetPrivateKey(isTelegram, isTelegram ? faucetPrivateKeyOrWalletName : null);
  if (!faucetKeyResult.success) {
    logs.push({ type: 'error', message: faucetKeyResult.message });
    if (telegramBot && chatId) telegramBot.sendMessage(chatId, faucetKeyResult.message);
    return { logs };
  }

  const faucetPrivateKey = faucetKeyResult.faucetPrivateKey;
  const faucetWallet = new ethers.Wallet(faucetPrivateKey, provider());
  const msg = `Checking faucet wallet balance (${faucetWallet.address})...`;
  logs.push({ type: 'loading', message: msg });
  if (telegramBot && chatId) telegramBot.sendMessage(chatId, msg);
  const faucetBalance = await provider().getBalance(faucetWallet.address);
  const faucetBalanceETH = parseFloat(ethers.formatEther(faucetBalance));
  if (faucetBalanceETH < amountETH * wallets.length) {
    const errMsg = `Faucet wallet ${faucetWallet.address} has insufficient ETH. Required: ${amountETH * wallets.length} ETH, Available: ${faucetBalanceETH} ETH`;
    logs.push({ type: 'error', message: errMsg });
    if (telegramBot && chatId) telegramBot.sendMessage(chatId, errMsg);
    return { logs };
  }

  const formattedAmount = parseFloat(amountETH.toFixed(18));
  const amountWei = ethers.parseEther(formattedAmount.toString());

  for (let i = 0; i < wallets.length; i++) {
    const walletInfo = wallets[i];
    if (!walletInfo.privatekey || !walletInfo.privatekey.startsWith('0x') || !/^(0x)[0-9a-fA-F]{64}$/.test(walletInfo.privatekey)) {
      const msg = `Skipping wallet '${walletInfo.name}': Invalid private key.`;
      logs.push({ type: 'warn', message: msg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, msg);
      continue;
    }

    let recipientWallet;
    try {
      recipientWallet = new ethers.Wallet(walletInfo.privatekey, provider());
    } catch (err) {
      const msg = `Skipping wallet '${walletInfo.name}': Failed to create wallet - ${err.message}`;
      logs.push({ type: 'warn', message: msg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, msg);
      continue;
    }

    const stepMsg = `Transferring ${formattedAmount} ETH to ${recipientWallet.address} (${walletInfo.name})`;
    logs.push({ type: 'step', message: stepMsg });
    if (telegramBot && chatId) telegramBot.sendMessage(chatId, stepMsg);
    try {
      const tx = await faucetWallet.sendTransaction({
        to: recipientWallet.address,
        value: amountWei
      });
      const receipt = await tx.wait();
      const successMsg = `${timelog()} | ETH Transfer Confirmed: ${explorer.tx(receipt.hash)}`;
      logs.push({ type: 'success', message: successMsg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, successMsg);
    } catch (err) {
      const errMsg = `ETH Transfer failed for ${recipientWallet.address}: ${err.message}`;
      logs.push({ type: 'error', message: errMsg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, errMsg);
    }

    if (i < wallets.length - 1) {
      const delayMsg = `Waiting ${delaySeconds} seconds before next transfer...`;
      logs.push({ type: 'info', message: delayMsg });
      if (telegramBot && chatId) telegramBot.sendMessage(chatId, delayMsg);
      await delay(delaySeconds * 1000);
    }
  }

  return { logs };
}

const MIN_TRANSACTIONS = 1;
const MAX_TRANSACTIONS = 100;
const MIN_THREADS = 1;
const MAX_THREADS = 10;
const MIN_PERCENT = 0.01;
const MAX_PERCENT = 100;
const MIN_DELAY = 0;
const MAX_DELAY = 60;

async function mainConsole() {
  header();

  let wallets = loadWallets();
  if (wallets.length === 0) {
    let privateKeys = [];
    try {
      const privateKeysContent = fs.readFileSync('private_keys.txt', 'utf8');
      privateKeys = privateKeysContent.split('\n').map(key => key.trim()).filter(key => key);
    } catch (err) {
      logger.error(`Failed to read private_keys.txt: ${err.message}`);
    }

    let babylonAddress = '';
    try {
      const babylonAddressesContent = fs.readFileSync('BABYLON_ADDRESS.txt', 'utf8');
      const addresses = babylonAddressesContent.split('\n').map(addr => addr.trim()).filter(addr => addr);
      if (addresses.length > 0) {
        babylonAddress = addresses[0];
      }
    } catch (err) {
      logger.error(`Failed to read BABYLON_ADDRESS.txt: ${err.message}`);
    }

    wallets = privateKeys.map((privateKey, index) => ({
      name: `Wallet${index + 1}`,
      privatekey: privateKey,
      babylonAddress
    }));
    saveWallets(wallets);
  }

  if (wallets.length === 0) {
    logger.error(`No valid wallets found. Ensure private_keys.txt or wallets.json contains valid entries.`);
    process.exit(1);
  }

  while (true) {
    console.log(`${colors.cyan}Menu:${colors.reset}`);
    console.log(`1. Sepolia - Holesky`);
    console.log(`2. Sepolia - Babylon`);
    console.log(`3. Random (Holesky and Babylon)`);
    console.log(`4. Exit`);
    console.log(`5. Faucet USDC Transfer (Sepolia)`);
    console.log(`6. Faucet ETH Transfer (Sepolia)`);
    const menuChoice = await askQuestion(`${colors.cyan}[?] Select menu option (1-6): ${colors.reset}`);
    const choice = parseInt(menuChoice.trim());

    if (choice === 4) {
      logger.info(`Exiting program.`);
      rl.close();
      process.exit(0);
    }

    if (![1, 2, 3, 5, 6].includes(choice)) {
      logger.error(`Invalid option. Please select 1, 2, 3, 4, 5, or 6.`);
      continue;
    }

    let numThreads, maxTransaction, minPercent, maxPercent, amountUSDC, amountETH, delaySeconds;

    const delayInput = await askQuestion(`${colors.cyan}[?] Enter delay between transactions RECOMMENDED FOR LOWER GAS USE (seconds, ${MIN_DELAY}-${MAX_DELAY}): ${colors.reset}`);
    delaySeconds = parseFloat(delayInput.trim());
    if (isNaN(delaySeconds) || delaySeconds < MIN_DELAY || delaySeconds > MAX_DELAY) {
      logger.error(`Invalid delay. Please enter a number between ${MIN_DELAY} and ${MAX_DELAY} seconds.`);
      continue;
    }

    if (choice === 1 || choice === 2 || choice === 3) {
      const numThreadsInput = await askQuestion(`${colors.cyan}[?] Enter the number of threads [${MIN_THREADS}-${MAX_THREADS}]: ${colors.reset}`);
      numThreads = parseInt(numThreadsInput.trim());
      if (isNaN(numThreads) || numThreads < MIN_THREADS || numThreads > MAX_THREADS) {
        logger.error(`Invalid number. Please enter a number between ${MIN_THREADS} and ${MAX_THREADS}.`);
        continue;
      }

      const maxTransactionInput = await askQuestion(`${colors.cyan}[?] Enter the number of transactions per wallet [${MIN_TRANSACTIONS}-${MAX_TRANSACTIONS}]: ${colors.reset}`);
      maxTransaction = parseInt(maxTransactionInput.trim());
      if (isNaN(maxTransaction) || maxTransaction < MIN_TRANSACTIONS || maxTransaction > MAX_TRANSACTIONS) {
        logger.error(`Invalid number. Please enter a number between ${MIN_TRANSACTIONS} and ${MAX_TRANSACTIONS}.`);
        continue;
      }

      const minPercentInput = await askQuestion(`${colors.cyan}[?] Enter the minimum percentage of USDC balance to use [${MIN_PERCENT}-${MAX_PERCENT}]: ${colors.reset}`);
      minPercent = parseFloat(minPercentInput.trim());
      if (isNaN(minPercent) || minPercent < MIN_PERCENT || minPercent > MAX_PERCENT) {
        logger.error(`Invalid percentage. Please enter a number between ${MIN_PERCENT} and ${MAX_PERCENT}.`);
        continue;
      }

      const maxPercentInput = await askQuestion(`${colors.cyan}[?] Enter the maximum percentage of USDC balance to use [${minPercent}-${MAX_PERCENT}]: ${colors.reset}`);
      maxPercent = parseFloat(maxPercentInput.trim());
      if (isNaN(maxPercent) || maxPercent < minPercent || maxPercent > MAX_PERCENT) {
        logger.error(`Invalid percentage. Please enter a number between ${minPercent} and ${MAX_PERCENT}.`);
        continue;
      }
    } else if (choice === 5) {
      const amountUSDCInput = await askQuestion(`${colors.cyan}[?] Enter the exact USDC amount to transfer per wallet (e.g., 10.5): ${colors.reset}`);
      amountUSDC = parseFloat(amountUSDCInput.trim());
      if (isNaN(amountUSDC) || amountUSDC <= 0) {
        logger.error(`Invalid USDC amount. Please enter a positive number.`);
        continue;
      }
    } else if (choice === 6) {
      const amountETHInput = await askQuestion(`${colors.cyan}[?] Enter the exact ETH amount to transfer per wallet (e.g., 0.01): ${colors.reset}`);
      amountETH = parseFloat(amountETHInput.trim());
      if (isNaN(amountETH) || amountETH <= 0) {
        logger.error(`Invalid ETH amount. Please enter a positive number.`);
        continue;
      }
    }

    const validWallets = wallets.filter(walletInfo => {
      if (!walletInfo.privatekey) {
        logger.warn(`Skipping wallet '${walletInfo.name}': Missing privatekey.`);
        return false;
      }
      if (!walletInfo.privatekey.startsWith('0x')) {
        logger.warn(`Skipping wallet '${walletInfo.name}': Privatekey must start with '0x'.`);
        return false;
      }
      if (!/^(0x)[0-9a-fA-F]{64}$/.test(walletInfo.privatekey)) {
        logger.warn(`Skipping wallet '${walletInfo.name}': Privatekey is not a valid 64-character hexadecimal string.`);
        return false;
      }
      return true;
    });

    if (validWallets.length === 0) {
      logger.warn(`No valid wallets to process. Check private_keys.txt or wallets.json for valid entries.`);
      continue;
    }

    if (choice === 1) {
      const result = await processWalletsInThreads(validWallets, numThreads, 'sendFromWallet', maxTransaction, 'holesky', minPercent, maxPercent, delaySeconds);
      result.logs.forEach(log => {
        logger[log.type](log.message);
      });
    } else if (choice === 2) {
      const result = await processWalletsInThreads(validWallets, numThreads, 'sendFromWallet', maxTransaction, 'babylon', minPercent, maxPercent, delaySeconds);
      result.logs.forEach(log => {
        logger[log.type](log.message);
      });
    } else if (choice === 3) {
      const result = await processWalletsInThreads(validWallets, numThreads, 'sendFromWalletRandom', maxTransaction, minPercent, maxPercent, delaySeconds);
      result.logs.forEach(log => {
        logger[log.type](log.message);
      });
    } else if (choice === 5) {
      const result = await faucetTransferUSDC(null, validWallets, amountUSDC, delaySeconds, false);
      result.logs.forEach(log => {
        logger[log.type](log.message);
      });
    } else if (choice === 6) {
      const result = await faucetTransferETH(null, validWallets, amountETH, delaySeconds, false);
      result.logs.forEach(log => {
        logger[log.type](log.message);
      });
    }

    if (validWallets.length === 0) {
      logger.warn(`No wallets processed. Check private_keys.txt or wallets.json for valid entries.`);
    }
  }
}

function mainTelegram() {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const allowedChatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !allowedChatId) {
    logger.warn('Telegram bot not configured: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not found in .env. Starting in console mode.');
    return mainConsole();
  }

  const bot = new TelegramBot(token, { polling: true });
  const userState = {};

  const mainMenu = {
    reply_markup: {
      inline_keyboard: [
        [{ text: 'Add Wallet', callback_data: 'add_wallet' }],
        [{ text: 'List Wallets', callback_data: 'list_wallets' }],
        [{ text: 'Run Transactions', callback_data: 'run_transactions' }],
        [{ text: 'Faucet Transfers', callback_data: 'faucet_transfers' }],
        [{ text: 'Help', callback_data: 'help' }],
      ],
    },
  };

  const backToHomeButton = [{ text: 'Back to Home', callback_data: 'home' }];

  function showMainMenu(chatId, message = 'Welcome to Union Testnet Auto Bot! Choose an option:') {
    delete userState[chatId];
    bot.sendMessage(chatId, message, mainMenu);
  }

  bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id.toString();
    if (chatId !== allowedChatId) {
      bot.sendMessage(chatId, 'Unauthorized access.');
      return;
    }
    showMainMenu(chatId);
  });

  bot.on('callback_query', async (query) => {
    const chatId = query.message.chat.id.toString();
    if (chatId !== allowedChatId) {
      bot.sendMessage(chatId, 'Unauthorized access.');
      bot.answerCallbackQuery(query.id);
      return;
    }

    const data = query.data;
    bot.answerCallbackQuery(query.id);

    if (data === 'home') {
      showMainMenu(chatId, 'Returned to main menu.');
      return;
    }

    if (data === 'start') {
      showMainMenu(chatId);
      return;
    }

    if (data === 'help') {
      bot.sendMessage(chatId, 'Available actions:\n- Add Wallet: Add a new wallet\n- List Wallets: View all wallets\n- Run Transactions: Execute transactions\n- Faucet Transfers: Transfer USDC or ETH\n- Help: Show this message', {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (data === 'add_wallet') {
      userState[chatId] = { step: 'add_wallet_input' };
      bot.sendMessage(chatId, 'Please provide wallet details in the format:\nname: <wallet_name>\nprivatekey: <private_key>\nbabylonAddress: <babylon_address> (optional)', {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (data === 'list_wallets') {
      const wallets = loadWallets();
      if (wallets.length === 0) {
        bot.sendMessage(chatId, 'No wallets found.', {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }
      const walletList = wallets.map(w => `Name: ${w.name}\nAddress: ${new ethers.Wallet(w.privatekey).address}\nBabylon Address: ${w.babylonAddress || 'N/A'}`).join('\n\n');
      bot.sendMessage(chatId, `Wallets:\n\n${walletList}`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (data === 'run_transactions') {
      userState[chatId] = { step: 'select_destination' };
      bot.sendMessage(chatId, 'Select destination:', {
        reply_markup: {
          inline_keyboard: [
            [{ text: 'Sepolia - Holesky', callback_data: 'destination_holesky' }],
            [{ text: 'Sepolia - Babylon', callback_data: 'destination_babylon' }],
            [{ text: 'Random (Holesky and Babylon)', callback_data: 'destination_random' }],
            backToHomeButton,
          ],
        },
      });
      return;
    }

    if (data === 'faucet_transfers') {
      userState[chatId] = { step: 'select_faucet_type' };
      bot.sendMessage(chatId, 'Select faucet transfer type:', {
        reply_markup: {
          inline_keyboard: [
            [{ text: 'USDC Transfer', callback_data: 'faucet_usdc' }],
            [{ text: 'ETH Transfer', callback_data: 'faucet_eth' }],
            backToHomeButton,
          ],
        },
      });
      return;
    }

    if (data.startsWith('destination_')) {
      const destination = data.split('_')[1];
      userState[chatId] = { step: 'enter_threads', destination };
      bot.sendMessage(chatId, `Enter the number of threads [${MIN_THREADS}-${MAX_THREADS}]:`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (data === 'faucet_usdc' || data === 'faucet_eth') {
      const faucetType = data.split('_')[1];
      const wallets = loadWallets();
      if (wallets.length === 0) {
        bot.sendMessage(chatId, 'No wallets found. Please add wallets first.', {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }
      userState[chatId] = { step: 'select_faucet_wallet', faucetType };
      const walletButtons = wallets.map(w => [{ text: w.name, callback_data: `wallet_${w.name}` }]);
      walletButtons.push(backToHomeButton);
      bot.sendMessage(chatId, 'Select the wallet to use as faucet:', {
        reply_markup: {
          inline_keyboard: walletButtons,
        },
      });
      return;
    }

    if (data.startsWith('wallet_')) {
      const walletName = data.split('_')[1];
      if (!userState[chatId] || !userState[chatId].faucetType) {
        bot.sendMessage(chatId, 'Error: Faucet type not selected. Please try again.', {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }
      userState[chatId] = { step: 'enter_faucet_amount', faucetType: userState[chatId].faucetType, faucetWalletName: walletName };
      bot.sendMessage(chatId, `Enter the exact ${userState[chatId].faucetType.toUpperCase()} amount to transfer per wallet (e.g., ${userState[chatId].faucetType === 'usdc' ? '10.5' : '0.01'}):`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }
  });

  bot.on('message', async (msg) => {
    const chatId = msg.chat.id.toString();
    if (chatId !== allowedChatId) {
      bot.sendMessage(chatId, 'Unauthorized access.');
      return;
    }

    if (msg.text && msg.text.startsWith('/')) {
      return;
    }

    if (!userState[chatId]) {
      showMainMenu(chatId, 'Please use the buttons to interact.');
      return;
    }

    const state = userState[chatId];

    if (state.step === 'add_wallet_input') {
      try {
        const lines = msg.text.split('\n').map(line => line.trim());
        const wallet = {};
        lines.forEach(line => {
          const [key, value] = line.split(':').map(s => s.trim());
          wallet[key] = value;
        });

        if (!wallet.name || !wallet.privatekey) {
          bot.sendMessage(chatId, 'Invalid format. Please provide name and privatekey.', {
            reply_markup: {
              inline_keyboard: [backToHomeButton],
            },
          });
          return;
        }
        if (!wallet.privatekey.startsWith('0x') || !/^(0x)[0-9a-fA-F]{64}$/.test(wallet.privatekey)) {
          bot.sendMessage(chatId, 'Invalid privatekey. Must be a 64-character hexadecimal string starting with 0x.', {
            reply_markup: {
              inline_keyboard: [backToHomeButton],
            },
          });
          return;
        }

        const wallets = loadWallets();
        wallets.push({
          name: wallet.name,
          privatekey: wallet.privatekey,
          babylonAddress: wallet.babylonAddress || ''
        });
        saveWallets(wallets);
        bot.sendMessage(chatId, `Wallet ${wallet.name} added successfully!`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        delete userState[chatId];
      } catch (err) {
        bot.sendMessage(chatId, `Error adding wallet: ${err.message}`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
      }
      return;
    }

    if (state.step === 'enter_threads') {
      const numThreads = parseInt(msg.text.trim());
      if (isNaN(numThreads) || numThreads < MIN_THREADS || numThreads > MAX_THREADS) {
        bot.sendMessage(chatId, `Invalid number. Please enter a number between ${MIN_THREADS} and ${MAX_THREADS}.`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }
      userState[chatId] = { step: 'enter_transactions', destination: state.destination, numThreads };
      bot.sendMessage(chatId, `Enter the number of transactions per wallet [${MIN_TRANSACTIONS}-${MAX_TRANSACTIONS}]:`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (state.step === 'enter_transactions') {
      const maxTransaction = parseInt(msg.text.trim());
      if (isNaN(maxTransaction) || maxTransaction < MIN_TRANSACTIONS || maxTransaction > MAX_TRANSACTIONS) {
        bot.sendMessage(chatId, `Invalid number. Please enter a number between ${MIN_TRANSACTIONS} and ${MAX_TRANSACTIONS}.`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }
      userState[chatId] = { step: 'enter_min_percent', destination: state.destination, numThreads: state.numThreads, maxTransaction };
      bot.sendMessage(chatId, `Enter the minimum percentage of USDC balance to use [${MIN_PERCENT}-${MAX_PERCENT}]:`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (state.step === 'enter_min_percent') {
      const minPercent = parseFloat(msg.text.trim());
      if (isNaN(minPercent) || minPercent < MIN_PERCENT || minPercent > MAX_PERCENT) {
        bot.sendMessage(chatId, `Invalid percentage. Please enter a number between ${MIN_PERCENT} and ${MAX_PERCENT}.`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }
      userState[chatId] = { step: 'enter_max_percent', destination: state.destination, numThreads: state.numThreads, maxTransaction: state.maxTransaction, minPercent };
      bot.sendMessage(chatId, `Enter the maximum percentage of USDC balance to use [${minPercent}-${MAX_PERCENT}]:`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (state.step === 'enter_max_percent') {
      const maxPercent = parseFloat(msg.text.trim());
      if (isNaN(maxPercent) || maxPercent < state.minPercent || maxPercent > MAX_PERCENT) {
        bot.sendMessage(chatId, `Invalid percentage. Please enter a number between ${state.minPercent} and ${MAX_PERCENT}.`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }
      userState[chatId] = { step: 'enter_delay', destination: state.destination, numThreads: state.numThreads, maxTransaction: state.maxTransaction, minPercent: state.minPercent, maxPercent };
      bot.sendMessage(chatId, `Enter delay between transactions (seconds, ${MIN_DELAY}-${MAX_DELAY}):`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (state.step === 'enter_delay') {
      const delaySeconds = parseFloat(msg.text.trim());
      if (isNaN(delaySeconds) || delaySeconds < MIN_DELAY || delaySeconds > MAX_DELAY) {
        bot.sendMessage(chatId, `Invalid delay. Please enter a number between ${MIN_DELAY} and ${MAX_DELAY} seconds.`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }

      const { destination, numThreads, maxTransaction, minPercent, maxPercent } = state;
      const wallets = loadWallets();
      if (wallets.length === 0) {
        bot.sendMessage(chatId, 'No wallets found. Please add wallets first.', {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        delete userState[chatId];
        return;
      }

      bot.sendMessage(chatId, `Starting ${maxTransaction} transaction(s) to ${destination} with ${numThreads} threads...`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });

      const validWallets = wallets.filter(walletInfo => {
        if (!walletInfo.privatekey) {
          bot.sendMessage(chatId, `Skipping wallet '${walletInfo.name}': Missing privatekey.`);
          return false;
        }
        if (!walletInfo.privatekey.startsWith('0x')) {
          bot.sendMessage(chatId, `Skipping wallet '${walletInfo.name}': Privatekey must start with '0x'.`);
          return false;
        }
        if (!/^(0x)[0-9a-fA-F]{64}$/.test(walletInfo.privatekey)) {
          bot.sendMessage(chatId, `Skipping wallet '${walletInfo.name}': Privatekey is not a valid 64-character hexadecimal string.`);
          return false;
        }
        return true;
      });

      if (validWallets.length === 0) {
        bot.sendMessage(chatId, 'No valid wallets to process. Check wallets.json for valid entries.', {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        delete userState[chatId];
        return;
      }

      let result;
      if (destination === 'holesky') {
        result = await processWalletsInThreads(validWallets, numThreads, 'sendFromWallet', maxTransaction, 'holesky', minPercent, maxPercent, delaySeconds);
      } else if (destination === 'babylon') {
        result = await processWalletsInThreads(validWallets, numThreads, 'sendFromWallet', maxTransaction, 'babylon', minPercent, maxPercent, delaySeconds);
      } else if (destination === 'random') {
        result = await processWalletsInThreads(validWallets, numThreads, 'sendFromWalletRandom', maxTransaction, minPercent, maxPercent, delaySeconds);
      }

      result.logs.forEach(log => {
        logger[log.type](log.message);
        if (log.message) bot.sendMessage(chatId, log.message);
      });

      bot.sendMessage(chatId, 'Transaction process completed.', {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      delete userState[chatId];
      return;
    }

    if (state.step === 'enter_faucet_amount') {
      const amount = parseFloat(msg.text.trim());
      if (isNaN(amount) || amount <= 0) {
        bot.sendMessage(chatId, `Invalid ${state.faucetType.toUpperCase()} amount. Please enter a positive number.`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }
      userState[chatId] = { step: 'enter_faucet_delay', faucetType: state.faucetType, amount, faucetWalletName: state.faucetWalletName };
      bot.sendMessage(chatId, `Enter delay between transfers (seconds, ${MIN_DELAY}-${MAX_DELAY}):`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      return;
    }

    if (state.step === 'enter_faucet_delay') {
      const delaySeconds = parseFloat(msg.text.trim());
      if (isNaN(delaySeconds) || delaySeconds < MIN_DELAY || delaySeconds > MAX_DELAY) {
        bot.sendMessage(chatId, `Invalid delay. Please enter a number between ${MIN_DELAY} and ${MAX_DELAY} seconds.`, {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        return;
      }

      const wallets = loadWallets();
      if (wallets.length === 0) {
        bot.sendMessage(chatId, 'No wallets found. Please add wallets first.', {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        delete userState[chatId];
        return;
      }

      const validWallets = wallets.filter(walletInfo => {
        if (!walletInfo.privatekey) {
          bot.sendMessage(chatId, `Skipping wallet '${walletInfo.name}': Missing privatekey.`);
          return false;
        }
        if (!walletInfo.privatekey.startsWith('0x')) {
          bot.sendMessage(chatId, `Skipping wallet '${walletInfo.name}': Privatekey must start with '0x'.`);
          return false;
        }
        if (!/^(0x)[0-9a-fA-F]{64}$/.test(walletInfo.privatekey)) {
          bot.sendMessage(chatId, `Skipping wallet '${walletInfo.name}': Privatekey is not a valid 64-character hexadecimal string.`);
          return false;
        }
        return true;
      });

      if (validWallets.length === 0) {
        bot.sendMessage(chatId, 'No valid wallets to process. Check wallets.json for valid entries.', {
          reply_markup: {
            inline_keyboard: [backToHomeButton],
          },
        });
        delete userState[chatId];
        return;
      }

      bot.sendMessage(chatId, `Starting ${state.faucetType.toUpperCase()} transfers to ${validWallets.length} wallets using wallet '${state.faucetWalletName}'...`, {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });

      let result;
      if (state.faucetType === 'usdc') {
        result = await faucetTransferUSDC(state.faucetWalletName, validWallets, state.amount, delaySeconds, true, bot, chatId);
      } else if (state.faucetType === 'eth') {
        result = await faucetTransferETH(state.faucetWalletName, validWallets, state.amount, delaySeconds, true, bot, chatId);
      }

      result.logs.forEach(log => {
        logger[log.type](log.message);
        if (log.message && telegramBot && chatId) telegramBot.sendMessage(chatId, log.message);
      });

      bot.sendMessage(chatId, 'Faucet transfer process completed.', {
        reply_markup: {
          inline_keyboard: [backToHomeButton],
        },
      });
      delete userState[chatId];
    }
  });

  logger.info('Telegram bot started with inline keyboard.');
}

async function processWalletsInThreads(wallets, numThreads, processFunction, ...args) {
  const threadCount = Math.min(numThreads, wallets.length, MAX_THREADS);
  const walletsPerThread = Math.ceil(wallets.length / threadCount);
  const tasks = [];
  const allLogs = [];

  for (let i = 0; i < threadCount; i++) {
    const start = i * walletsPerThread;
    const end = Math.min(start + walletsPerThread, wallets.length);
    const threadWallets = wallets.slice(start, end);
    if (threadWallets.length > 0) {
      tasks.push(runWorker({ wallets: threadWallets, processFunction, args }));
    }
  }

  const results = await Promise.all(tasks);
  results.forEach(result => {
    if (result.logs) allLogs.push(...result.logs);
  });

  return { logs: allLogs };
}

async function runWorker(workerData) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData });
    worker.on('message', (result) => resolve(result));
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0) reject(new Error(`Worker stopped with exit code ${code}`));
    });
  });
}

if (isMainThread) {
  async function main() {
    try {
      if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
        mainTelegram();
      } else {
        mainConsole();
      }
    } catch (err) {
      logger.error(`Main error: ${err.message}`);
      rl.close();
      process.exit(1);
    }
  }

  main();
} else {
  async function sendFromWalletRandom(walletInfo, maxTransaction, minPercent, maxPercent, delaySeconds) {
    const logs = [];
    const destinations = ['holesky', 'babylon'].filter(dest => dest !== 'babylon' || walletInfo.babylonAddress);
    if (destinations.length === 0) {
      const msg = `Skipping wallet '${walletInfo.name}': No valid destinations (missing babylonAddress).`;
      logs.push({ type: 'warn', message: msg });
      return { logs };
    }
    for (let i = 0; i < maxTransaction; i++) {
      const randomDest = destinations[Math.floor(Math.random() * destinations.length)];
      const result = await sendFromWallet(walletInfo, 1, randomDest, minPercent, maxPercent, delaySeconds);
      logs.push(...result.logs);
      if (i < maxTransaction - 1) {
        const msg = `Waiting ${delaySeconds} seconds before next transaction...`;
        logs.push({ type: 'info', message: msg });
        await delay(delaySeconds * 1000);
      }
    }
    return { logs };
  }

  const { wallets, processFunction, args } = workerData;
  let fn;
  if (processFunction === 'sendFromWallet') {
    fn = sendFromWallet;
  } else if (processFunction === 'sendFromWalletRandom') {
    fn = sendFromWalletRandom;
  }

  async function run() {
    const allLogs = [];
    for (const walletInfo of wallets) {
      const result = await fn(walletInfo, ...args);
      allLogs.push(...result.logs);
    }
    parentPort.postMessage({ logs: allLogs });
  }

  run().catch(err => {
    console.error(`Worker error: ${err.message}`);
    parentPort.postMessage({ logs: [{ type: 'error', message: `Worker error: ${err.message}` }] });
  });
}
