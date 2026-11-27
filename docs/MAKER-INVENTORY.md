# How inventory stays balanced

A maker holds two things: XMR (or ZEC, or HYPE/USDC on the EVM side) and SOL. SOL → XMR swaps use up XMR and bring in SOL. XMR → SOL swaps do the reverse. If a maker only ever filled one direction it would run out of XMR, so the daemon has two tools that keep both sides stocked. User swaps never change: they stay atomic and trustless on chain.

## 1. Prices lean against the side running low (on by default)

Each maker aims for a split by value, 50/50 unless you set `skew.target`. While both sides are within 10% of target, quotes use your normal spread. As XMR drops below target:

- **SOL → XMR quotes get wider**, smoothly, by up to 1.5% (`skew.maxWidenBps`, default 150). Takers who compare makers go elsewhere for this direction.
- **XMR → SOL quotes get tighter**, by up to 1% (`skew.maxImproveBps`, default 100), and never better than mid. Takers selling XMR come to you.

The same works in reverse when SOL runs low. A large swap is priced at the point halfway through the move it causes, so splitting one swap into several doesn't get a better price.

If a swap would leave a side below 10% of its target (`skew.floor`), the maker **stops quoting that direction** until inventory recovers. The other direction stays open. Users see "this maker is low on XMR right now" at the quote step and move to another maker, instead of a swap failing partway through. `/v1/info` shows the current spread per direction as `spreadNow`; `null` means paused.

The OTC desk, the ZEC desk (`zec.skew`) and the EVM maker (`skew`) use the same rule. Set `"skew": { "enabled": false }` to quote a flat spread.

## 2. Auto-refill with your own funds (off by default)

If flow stays one-sided, prices alone may not be enough. With `refill.enabled`, once a side drops below `refill.triggerPct` of its target (default 30%), the daemon swaps some of **your own surplus** from the other side through an instant exchanger. It sends the result to a fresh address in your own wallet.

- **Route.** The first route is Trocador (`refill.route: "trocador"`). It's an aggregator that returns the best quote from several instant exchangers. By default it accepts only providers rated A for KYC (no KYC holds) and B or better for logging. You need a Trocador API key in `refill.apiKeyFile`. Routes plug in behind one interface (`maker/exchangers.ts`).
- **Limits.**
  - Each refill is at most `chunkSol` (default 5 SOL worth).
  - At most `dailyCapSol` leaves per rolling 24 hours (default 20 SOL worth).
  - A refill is skipped when the exchanger would pay more than `maxSlippageBps` below the market mid (default 1.5%, all fees included).
  - Refills need a live price that is less than 5 minutes old.
- **Receipts.** Every step is written to `refill.jsonl` next to your journal: the exchange id, the deposit address, your payment tx, the exchanger's payout tx, the tx ids that arrived in your wallet, and the cost against mid. XMR arrives on a subaddress made for that refill, so each delivery is matched to its refill. It counts as inventory once it unlocks (10 confirmations). While a refill is on its way, the price balancing counts the coins as already arriving.
- **Safety.**
  - Only one refill runs at a time.
  - Refills pause and alert (`alertUrl`, plus the log) in these cases: the exchanger fails, holds or refunds the order; the coins don't arrive within `deliverMins` (default 90); or the daemon restarts in the middle of a payment.
  - Nothing is ever re-sent automatically. Delete `refill.PAUSED` to resume.
  - Refills run only on mainnet.

**What you take on.** While a refill is in flight, the exchanger holds that chunk of your money. That is custodial for you, the maker, up to the caps above. An exchanger can delay an order or ask for KYC. It never touches a user's swap: users swap against the on-chain escrow and the coins you already hold. If you don't want any third party involved, leave refill off. The price balancing above uses no one else.

**There is no fully non-custodial refill route today.** BTC → XMR atomic swaps (eigenwallet) are live, but only through a GUI and only in one direction. There's no XMR → SOL route without a custodian.

## What the calculator on /makers shows

Turnover is arithmetic on your inputs. It shows how fast one-way flow would use your inventory with no balancing and no refills. The auto-refill row adds the refill cost you enter, within the daily cap. Neither is a forecast.
