/**
 * Scam Arena content. Everything here is FICTIONAL: brands, domains and payees are invented,
 * and no scenario collects data or moves money.
 * The participant's "learning score" is separate from the backend's official risk_score.
 */

export interface Indicator {
  id: string;
  /** Short name shown in the results list. */
  label: string;
  /** false = a decoy that looks odd but is normal. Flagging it costs points. */
  suspicious: boolean;
  explanation: string;
}

export interface Scenario {
  slug: string;
  title: string;
  tagline: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  /** Sent to POST /api/v1/scan/url with source "arena". Never fetched by the backend. */
  scan: { url: string; page_title: string; page_text: string; links: string[] };
  indicators: Indicator[];
}

export const POINTS_CORRECT = 10;
export const POINTS_FALSE_FLAG = 5;

export const SCENARIOS: Scenario[] = [
  {
    slug: "banking-kyc",
    title: "Urgent KYC update",
    tagline: "A bank says your account will be frozen unless you verify today.",
    difficulty: "Beginner",
    scan: {
      url: "https://novatrust-kyc-verify.account-secure.top/update",
      page_title: "Nova Trust Bank - KYC Verification",
      page_text:
        "Nova Trust Bank. Customer care. Branch locator. URGENT: Your account will be suspended in 24 hours. Dear Customer, your KYC is expire, update now to avoid permanent block. Net banking user ID. Net banking password. ATM PIN. Enter the OTP sent to your mobile. 100% Secure Verified Site. Copyright 2026 Nova Trust Bank.",
      links: ["https://novatrust-kyc-verify.account-secure.top/submit"],
    },
    indicators: [
      { id: "domain", label: "Look-alike domain", suspicious: true, explanation: "The bank's name is stuffed into an unrelated .top domain. Real banks use their own short, registered domain." },
      { id: "urgency", label: "Suspension deadline", suspicious: true, explanation: "A 24-hour threat is a pressure tactic. Banks don't freeze accounts through a surprise web form." },
      { id: "grammar", label: "Broken grammar", suspicious: true, explanation: "\"Your KYC is expire\" and a generic \"Dear Customer\" suggest a copied template, not official communication." },
      { id: "password", label: "Password and ATM PIN request", suspicious: true, explanation: "No legitimate KYC process asks for your net-banking password or ATM PIN." },
      { id: "otp", label: "OTP request", suspicious: true, explanation: "An OTP typed into a web form lets the attacker approve a transaction or log in as you." },
      { id: "badge", label: "Self-made \"100% Secure\" badge", suspicious: true, explanation: "Anyone can paste a trust badge on a page. It proves nothing about the site." },
      { id: "nav", label: "Customer care / branch links", suspicious: false, explanation: "Standard navigation links appear on every bank site. On their own they say nothing about trust." },
      { id: "footer", label: "Copyright footer", suspicious: false, explanation: "A copyright line is easy to fake and equally common on real sites. It's not evidence either way." },
    ],
  },
  {
    slug: "upi-reward",
    title: "Cashback reward claim",
    tagline: "A payment app says you won money, but you need to pay first.",
    difficulty: "Intermediate",
    scan: {
      url: "http://quickpay-cashback-claim.win/rewards",
      page_title: "QuickPay Rewards - Claim your cashback",
      page_text:
        "QuickPay Rewards. Congratulations! You have won Rs 50,000 cashback. Offer expires in 09:59. Pay a processing fee of Rs 499 to receive your cashback. Pay to: rewards.claim8841@okpay. Scan this QR with any UPI app to receive your money. Ramesh from Pune claimed Rs 50,000 two minutes ago. Help center. Terms apply. Copyright 2026 QuickPay.",
      links: ["http://quickpay-cashback-claim.win/pay"],
    },
    indicators: [
      { id: "url", label: "Unencrypted throwaway domain", suspicious: true, explanation: "A payment page on plain http:// and a disposable .win domain isn't how a real payments company operates." },
      { id: "reward", label: "Unrealistic reward", suspicious: true, explanation: "Unexpected prizes you never entered for are bait. The bigger the amount, the louder the alarm." },
      { id: "countdown", label: "Countdown timer", suspicious: true, explanation: "A ticking clock is designed to stop you thinking or checking with someone." },
      { id: "fee", label: "Fee to receive money", suspicious: true, explanation: "You never pay to receive a reward. A \"processing fee\" is the actual scam." },
      { id: "payee", label: "Personal-looking payee ID", suspicious: true, explanation: "A random-looking UPI ID is an individual's account, not a verified merchant." },
      { id: "qr", label: "\"Scan to receive\" QR code", suspicious: true, explanation: "Scanning a QR or approving a request sends money out. You never need either to receive money." },
      { id: "proof", label: "Fake social proof", suspicious: true, explanation: "A live-looking \"someone just claimed\" ticker is trivial to fake and exists to make you feel safe." },
      { id: "help", label: "Help center link", suspicious: false, explanation: "A help link is ordinary. Scammers include it too, so it neither proves nor disproves anything." },
      { id: "terms", label: "\"Terms apply\" footer", suspicious: false, explanation: "Standard small print appears on real offers as well. Judge the offer itself, not the footer." },
    ],
  },
  {
    slug: "fake-job",
    title: "Work-from-home job offer",
    tagline: "An easy high-paying job that asks you for money before you start.",
    difficulty: "Advanced",
    scan: {
      url: "https://brightpath-careers-hiring.work-apply.click/apply",
      page_title: "BrightPath Careers - Data Entry Executive",
      page_text:
        "BrightPath Careers. Data Entry Executive, work from home. Earn Rs 60,000 per month working 2 hours a day. No experience or interview needed. Instant offer letter. Registration fee Rs 1,999, fully refundable. Only 3 seats left, pay within 30 minutes. Contact our recruiter on WhatsApp only. Responsibilities: update spreadsheets, maintain records. Office: Bengaluru. Equal opportunity employer. Apply now.",
      links: ["https://bp-go.click/apply"],
    },
    indicators: [
      { id: "salary", label: "Too-good pay for little work", suspicious: true, explanation: "Rs 60,000 for two hours with no experience doesn't match any real data-entry job." },
      { id: "offer", label: "Instant offer, no interview", suspicious: true, explanation: "Real employers screen candidates. An offer before any interview is a hook." },
      { id: "fee", label: "Registration fee", suspicious: true, explanation: "Legitimate employers never charge you to be hired. \"Refundable\" fees are not refunded." },
      { id: "seats", label: "Seats-left deadline", suspicious: true, explanation: "A 30-minute payment window creates panic so you skip verification." },
      { id: "whatsapp", label: "WhatsApp-only recruiter", suspicious: true, explanation: "Recruiters who avoid company email and phone are hiding an identity that can't be checked." },
      { id: "applink", label: "Apply link to a different domain", suspicious: true, explanation: "The Apply button leads to a short-link domain unrelated to the company. Hover before you click." },
      { id: "roles", label: "Job responsibilities list", suspicious: false, explanation: "A plain description of duties is normal. Scammers copy real job text, so it's not a signal alone." },
      { id: "address", label: "Office city", suspicious: false, explanation: "Naming a city is routine. It's only useful if you can verify the company actually exists there." },
      { id: "eoe", label: "Equal-opportunity line", suspicious: false, explanation: "This boilerplate appears on real postings too. It's not evidence." },
    ],
  },
];

export function getScenario(slug: string): Scenario | undefined {
  return SCENARIOS.find((s) => s.slug === slug);
}

export interface Grade {
  correct: string[];
  missed: string[];
  falseFlags: string[];
  score: number;
  max: number;
}

export function gradeAnswers(scenario: Scenario, flagged: Set<string>): Grade {
  const correct: string[] = [];
  const missed: string[] = [];
  const falseFlags: string[] = [];
  for (const ind of scenario.indicators) {
    const on = flagged.has(ind.id);
    if (ind.suspicious && on) correct.push(ind.id);
    else if (ind.suspicious) missed.push(ind.id);
    else if (on) falseFlags.push(ind.id);
  }
  const max = scenario.indicators.filter((i) => i.suspicious).length * POINTS_CORRECT;
  const score = Math.max(0, correct.length * POINTS_CORRECT - falseFlags.length * POINTS_FALSE_FLAG);
  return { correct, missed, falseFlags, score, max };
}

// Only numeric challenge scores are stored locally. No scan input or message text is ever persisted.
const STORE_KEY = "psx_arena_best";

export function loadBestScores(): Record<string, { score: number; max: number }> {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY) ?? "{}");
  } catch {
    return {};
  }
}

export function saveBestScore(slug: string, score: number, max: number) {
  try {
    const all = loadBestScores();
    if (!all[slug] || score > all[slug].score) all[slug] = { score, max };
    localStorage.setItem(STORE_KEY, JSON.stringify(all));
  } catch {
    /* storage unavailable: scores simply aren't remembered */
  }
}
