# Union Testnet Auto Bot

A Node.js-based automation bot for interacting with the Union Testnet, supporting transactions from Sepolia to Holesky and Babylon networks. The bot includes a Telegram interface with inline keyboards for user-friendly interaction, allowing users to manage wallets and execute transactions seamlessly.

## Features
- **Automated Transactions**: Send transactions from Sepolia to Holesky or Babylon with configurable transaction counts.
- **Telegram Integration**: Control the bot via a Telegram interface with inline buttons for adding wallets, listing wallets, and running transactions.
- **Wallet Management**: Add and store wallets securely in a JSON file, with support for Babylon addresses.
- **Error Handling**: Robust validation for private keys and transaction parameters.
- **Console Mode**: Fallback to a command-line interface if Telegram is not configured.

## Prerequisites
- Node.js (v18.20.8 or later)
- A Telegram bot token (obtained from [@BotFather](https://t.me/BotFather))
- An Ethereum wallet with Sepolia testnet funds (USDC)
- Optional: A Babylon address for cross-chain transactions

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/sinak1023/union-testne-bot.git
   cd union-testne-bot
   ```

2. **Install Dependencies**:
   ```bash
   npm install ethers axios moment-timezone node-telegram-bot-api dotenv
   ```

3. **Set Up Environment Variables**:
   Create a `.env` file in the project root and add the following:
   ```env
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token
   TELEGRAM_CHAT_ID=your_telegram_chat_id
   PRIVATE_KEY_1=0xYourPrivateKey1
   BABYLON_ADDRESS_1=YourBabylonAddress1
   PRIVATE_KEY_2=0xYourPrivateKey2
   BABYLON_ADDRESS_2=YourBabylonAddress2
   ```
   - Replace `your_telegram_bot_token` with the token from @BotFather.
   - Replace `your_telegram_chat_id` with your Telegram chat ID (get it from @userinfobot).
   - Ensure private keys start with `0x` and are 64-character hexadecimal strings.

4. **Run the Bot**:
   ```bash
   node telegram_bot.js
   ```

## Usage
### Telegram Mode
1. Start the bot by sending `/start` to your Telegram bot.
2. Use the inline buttons to:
   - **Add Wallet**: Provide wallet details (name, private key, optional Babylon address).
   - **List Wallets**: View all stored wallets.
   - **Run Transactions**: Select a destination (Sepolia to Holesky, Babylon, or Random) and specify the number of transactions.
   - **Help**: View available actions.
3. Use the **Back to Home** button to cancel any operation and return to the main menu.

### Console Mode
If Telegram is not configured, the bot runs in console mode:
1. Select a menu option (1-4) to choose the transaction destination.
2. Enter the number of transactions per wallet.
3. The bot processes transactions and logs results.

## Security Notes
- **Private Keys**: Stored in `wallets.json` and `.env`. Keep these files secure and never share them.
- **Telegram Access**: Only the user with the specified `TELEGRAM_CHAT_ID` can interact with the bot.
- **Testnet Only**: Use testnet funds (Sepolia USDC) to avoid real asset loss.

## Support the Project
If you find this bot useful, consider buying me a coffee! ☕

- **Ethereum (Base)**: `0x7A43342707de2FA07b0C4cCe132dFD49fdA2a711`

## Contributing
Feel free to open issues or submit pull requests on [GitHub](https://github.com/sinak1023/union-testnet-bot). Feedback and improvements are welcome!
