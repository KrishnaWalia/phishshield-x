"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { getScenario } from "@/lib/arena";
import { ArenaChallenge } from "@/components/arena/ArenaChallenge";
import { PageHeader } from "@/components/ui";

export default function ArenaScenarioPage() {
  const { slug } = useParams<{ slug: string }>();
  const scenario = getScenario(slug);

  if (!scenario) {
    return (
      <div className="panel p-6">
        <p className="font-display text-lg text-white">Scenario not found</p>
        <p className="mt-1 text-sm text-slate-400">There is no Arena scenario called &ldquo;{slug}&rdquo;.</p>
        <Link href="/arena" className="btn-primary mt-4">Back to Scam Arena</Link>
      </div>
    );
  }

  return (
    <>
      <PageHeader
        title={scenario.title}
        description={scenario.tagline}
        action={<Link href="/arena" className="btn-ghost">All scenarios</Link>}
      />
      <ArenaChallenge scenario={scenario} />
    </>
  );
}
