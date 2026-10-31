"use client";

import type { ReactNode } from "react";
import { Hot } from "./Hot";

/** Simulated browser window. The address bar is part of the puzzle. */
function BrowserFrame({ url, children }: { url: ReactNode; children: ReactNode }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-600 bg-white shadow-2xl shadow-black/40">
      <div className="flex items-center gap-3 bg-slate-800 px-3 py-2.5">
        <div className="flex gap-1.5"><i className="h-2.5 w-2.5 rounded-full bg-slate-600" /><i className="h-2.5 w-2.5 rounded-full bg-slate-600" /><i className="h-2.5 w-2.5 rounded-full bg-slate-600" /></div>
        <div className="min-w-0 flex-1 truncate rounded-md bg-slate-950 px-3 py-1.5 text-xs text-slate-200">{url}</div>
      </div>
      {children}
      <div className="bg-slate-100 px-4 py-2 text-center text-[11px] text-slate-500">
        Training simulation. This page is fictional and nothing you click is sent anywhere.
      </div>
    </div>
  );
}

/** Inert, display-only field: never an <input>, so no real data can be typed or collected. */
function FakeField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="mb-1 text-xs font-medium text-slate-600">{label}</p>
      <div className="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-400">{value}</div>
    </div>
  );
}

export function BankingKycPage() {
  return (
    <BrowserFrame url={<Hot id="domain" as="span">https://novatrust-kyc-verify.account-secure.top/update</Hot>}>
      <div className="bg-slate-50 text-slate-900">
        <div className="flex flex-wrap items-center justify-between gap-2 bg-blue-900 px-5 py-3 text-white">
          <span className="text-lg font-bold">Nova Trust Bank</span>
          <Hot id="nav" className="flex gap-4 px-1 text-xs"><span>Customer care</span><span>Branch locator</span></Hot>
        </div>
        <Hot id="urgency" className="bg-red-600 px-5 py-3 text-center text-sm font-semibold text-white">
          URGENT: Your account will be suspended in 24 hours!
        </Hot>
        <div className="mx-auto max-w-md space-y-4 p-6">
          <Hot id="grammar" className="p-1">
            <h3 className="text-lg font-bold">KYC Verification</h3>
            <p className="mt-1 text-sm text-slate-600">Dear Customer, your KYC is expire. Update now to avoid permanent block of account.</p>
          </Hot>
          <FakeField label="Net banking user ID" value="Simulated field" />
          <Hot id="password" className="space-y-3 p-1">
            <FakeField label="Net banking password" value="••••••••" />
            <FakeField label="ATM PIN" value="••••" />
          </Hot>
          <Hot id="otp" className="p-1"><FakeField label="Enter OTP sent to your mobile" value="------" /></Hot>
          <div className="w-full rounded-md bg-blue-900 py-2.5 text-center text-sm font-semibold text-white opacity-70">Verify now (inactive)</div>
          <Hot id="badge" className="mx-auto w-fit rounded-full border border-emerald-600 px-3 py-1 text-xs font-semibold text-emerald-700">100% Secure · Verified Site</Hot>
        </div>
        <Hot id="footer" className="border-t border-slate-200 px-5 py-3 text-center text-xs text-slate-500">© 2026 Nova Trust Bank</Hot>
      </div>
    </BrowserFrame>
  );
}

/** Decorative, deterministic pattern. It is NOT a scannable QR code. */
function FakeQr() {
  const cells = Array.from({ length: 121 }, (_, n) => {
    const i = Math.floor(n / 11), j = n % 11;
    return (i * 7 + j * 13 + i * j) % 3 === 0;
  });
  return (
    <div className="grid h-28 w-28 grid-cols-11 gap-px bg-white p-1.5" aria-label="Simulated QR code, not scannable">
      {cells.map((on, n) => <i key={n} className={on ? "bg-slate-900" : "bg-white"} />)}
    </div>
  );
}

export function UpiRewardPage() {
  return (
    <BrowserFrame url={<Hot id="url" as="span">http://quickpay-cashback-claim.win/rewards</Hot>}>
      <div className="bg-gradient-to-b from-violet-50 to-white text-slate-900">
        <div className="flex items-center justify-between px-5 py-3">
          <span className="text-lg font-bold text-violet-800">QuickPay Rewards</span>
          <Hot id="help" as="span" className="px-1 text-xs text-slate-500">Help center</Hot>
        </div>
        <div className="mx-auto max-w-md space-y-4 p-6 text-center">
          <Hot id="reward" className="p-2"><p className="text-sm text-slate-600">Congratulations!</p><p className="text-3xl font-extrabold text-violet-800">You won ₹50,000 cashback</p></Hot>
          <Hot id="countdown" className="mx-auto w-fit rounded-md bg-red-100 px-4 py-1.5 text-sm font-semibold text-red-700">Offer expires in 09:59</Hot>
          <Hot id="fee" className="rounded-lg border border-violet-200 bg-white p-3 text-sm">Pay a processing fee of <b>₹499</b> to receive your cashback.</Hot>
          <Hot id="payee" className="rounded-lg bg-slate-100 p-3 text-sm"><span className="text-slate-500">Pay to: </span><b>rewards.claim8841@okpay</b></Hot>
          <Hot id="qr" className="mx-auto w-fit p-2">
            <div className="mx-auto w-fit rounded-lg border border-slate-300 bg-white p-1"><FakeQr /></div>
            <p className="mt-1.5 text-xs text-slate-600">Scan this QR with any UPI app to receive your money</p>
          </Hot>
          <Hot id="proof" className="rounded-md bg-emerald-50 px-3 py-2 text-xs text-emerald-800">Ramesh from Pune claimed ₹50,000 two minutes ago</Hot>
        </div>
        <Hot id="terms" className="border-t border-slate-200 px-5 py-3 text-center text-xs text-slate-500">Terms apply · © 2026 QuickPay</Hot>
      </div>
    </BrowserFrame>
  );
}

export function FakeJobPage() {
  return (
    <BrowserFrame url={<Hot id="applink" as="span">https://brightpath-careers-hiring.work-apply.click/apply <span className="text-slate-400">(Apply → bp-go.click/apply)</span></Hot>}>
      <div className="bg-white text-slate-900">
        <div className="bg-teal-700 px-5 py-3 text-lg font-bold text-white">BrightPath Careers</div>
        <div className="mx-auto max-w-lg space-y-4 p-6">
          <div>
            <h3 className="text-xl font-bold">Data Entry Executive · Work from home</h3>
            <Hot id="salary" className="mt-2 p-1 text-sm">Earn <b>₹60,000 per month</b> working just 2 hours a day. No experience needed.</Hot>
          </div>
          <Hot id="offer" className="rounded-md bg-teal-50 p-3 text-sm">Instant offer letter. No interview required.</Hot>
          <Hot id="fee" className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm">Registration fee <b>₹1,999</b> (fully refundable)</Hot>
          <Hot id="seats" className="text-sm font-semibold text-red-700"><span className="p-1">Only 3 seats left! Pay within 30 minutes.</span></Hot>
          <Hot id="whatsapp" className="rounded-md bg-slate-100 p-3 text-sm">Contact our recruiter on WhatsApp only.</Hot>
          <Hot id="roles" className="p-1 text-sm text-slate-600"><p className="font-semibold text-slate-800">Responsibilities</p><ul className="ml-4 list-disc"><li>Update spreadsheets</li><li>Maintain records</li></ul></Hot>
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
            <Hot id="address" as="span" className="px-1">Office: Bengaluru</Hot>
            <Hot id="eoe" as="span" className="px-1">Equal opportunity employer</Hot>
          </div>
          <div className="w-full rounded-md bg-teal-700 py-2.5 text-center text-sm font-semibold text-white opacity-70">Apply now (inactive)</div>
        </div>
      </div>
    </BrowserFrame>
  );
}

export const SCENARIO_PAGES: Record<string, () => JSX.Element> = {
  "banking-kyc": BankingKycPage,
  "upi-reward": UpiRewardPage,
  "fake-job": FakeJobPage,
};
