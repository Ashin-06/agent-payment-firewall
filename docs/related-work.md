# Related work

What this project takes from others, and where it differs. This is a short review of what could be read, not a full survey. Numbers below are as those authors report them, and they can't be compared with this project's, since the tasks and models differ.

## Research

**[AgentAbstain](https://arxiv.org/abs/2607.10059)** measures whether agents know when not to act, using 263 paired tasks: one where the agent should act, and one where it should abstain. A pair counts only if both are right. Across 17 frontier LLMs the best agent reached 59.5%. It names post-hoc abstention as a key failure: agents take an irreversible action, then notice the reason they shouldn't have.

This project borrows the scoring for `python -m agentfw paired`, and the undo window exists because of that failure. The two measure different things: AgentAbstain scores the agent, while here the agent always tries, so the score belongs to the firewall.

**[GateArena](https://neurips.cc/virtual/2026/168290)** (Jiang, Quinzan and Bhatt, NeurIPS 2026 workshop) binds each confirmation to a token for the exact parameters, and the tool refuses a call with a missing, spent or mismatched token. Moving the check into the handler took protocol violations from 91 of 400 to 0 of 400. The approvals here work the same way, so that part isn't new. Mandates address the step before: what happens when nobody was asked for a confirmation at all.

**[Adaptive evaluation of out-of-band defences](https://arxiv.org/abs/2606.26479)** points out that CaMeL, FIDES, Progent and similar systems have been tested only on static attack sets, and that earlier defences which looked strong that way later fell to defence-aware attacks. Its recommendation led to two things here:

- an adaptive attacker in `python -m agentfw redteam`, which knows the rules and searches for a way through;
- repeated attack rounds on this project's own parser, where each round found real holes in a version that had passed everything before.

That paper also calls for stronger optimised attacks such as white-box GCG. Those target the model, and this evaluation already assumes the model is fully compromised, so they wouldn't change these results. The search here is simple hill climbing on the gateway's logic, not a proof.

**[CaMeL](https://arxiv.org/abs/2503.18813)** separates trusted control flow from untrusted data and attaches capabilities to values, solving 77% of AgentDojo tasks with provable security against 84% undefended. It is more general, and it changes how the agent runs. This project is narrower: one domain, no change to the agent, and a cost in confirmations rather than in completed tasks.

## Standards and rules

**[AP2, the Agent Payments Protocol](https://github.com/google-agentic-commerce/AP2)** uses signed mandates as proof of what a user authorised. The mandate details here come from secondary summaries, not the specification. The word is shared but the job is different: AP2 carries authority that a user has signed, while mandates here derive it from a chat message, where no signature exists. A real deployment could use both.

**[RBI's authentication directions, 2025](https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=12898&Mode=0)** require at least two factors for digital payments in India, unless exempted, with one dynamic for transactions that aren't card-present, from 1 April 2026. Nothing in this firewall replaces that. A mandate isn't a factor of authentication, so in production the bank's own authentication still applies, and payments marked "allowed" here would still need it.

**[RBI's beneficiary name look-up](https://resources.probe42.in/regulatory-updates/rbi-circulars/rbi-circular-beneficiary-name-look-up-for-rtgs-and-neft-transactions/)** (circular RBI/2024-25/99) asked banks to offer an account-name check for RTGS and NEFT by 1 April 2025, and lets the customer proceed at their discretion if the name can't be shown. The account-name check here is built to use it. Whether a given bank exposes this to software isn't something this project has checked.

## Similar projects

[Tessera](https://pypi.org/project/cloudmorph-tessera/0.7.2/), [SpendShield](https://enterprisedna.co/directories/mcp/felixpg13-glitch-spendshield) and [Tollgate](https://glama.ai/mcp/servers/prithvipm412/tollgate/tree) also put a deterministic check between an agent and its tools, with allow, approve and deny outcomes, and in some cases audit logs or budgets. Only their project pages were read, and none has been run here. On those pages, decisions come from configured policy.

## What is different here

- Authority comes from what the customer actually said, is spent once, and is denied by default. Any word the rules don't know means no authority.
- Provenance and mandates work together, so an account the customer never typed is refused even if every approval is rubber-stamped.
- Risky payments that are allowed still wait out an undo window, because a later refusal can't undo a sent payment.
- The receiving bank's own record of the account name is checked against the name the customer gave.
- An independent last check before the bank holds even with every rule bypassed, which is tested by bypassing them.
- The oracle shares no code with the rules, and the same oracle catches the firewall when a layer is removed.
- The attack history is published, including what each round broke.

None of this has been independently reviewed.
