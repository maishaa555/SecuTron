# Hackathon and demo checklist

## Official requirements to confirm again

- [ ] Read current [official rules](https://nebiusglobalaihackathon.devpost.com/rules), project overview, judging criteria, and submission fields.
- [ ] Confirm eligible work period, deadline, team eligibility, licensing, and any attribution requirements.
- [ ] Confirm a working application uses Nebius Token Factory or Nebius AI Cloud and at least one NVIDIA open-source model.
- [ ] Select the Coding and Agentic Engineering track only if the delivered project demonstrates an actual plan/write/test/iterate workflow; otherwise reassess fit.
- [ ] Public repository, open-source license, setup instructions, English materials, and public demo video if required by the final rules.
- [ ] No unsupported performance, coverage, or accuracy claims.

## Demo story (target 2:30–2:50, verify limit)

1. Show the intentionally vulnerable Python fixture repository.
2. Run local Rust scan and open the SQL finding with its source-to-sink evidence.
3. Request explanation; show that the model is Nemotron served through Nebius Token Factory, with minimized evidence.
4. Request a bounded fix proposal.
5. Review diff, run selected tests in a disposable copy, and rescan.
6. Show the actual validation outcome, including any failure or residual finding.
7. State the MVP's narrow language/rule coverage and model's role honestly.

## Submission assets still to create

- Public repository and chosen license.
- Source implementation and fixture corpus (an initial `vulnerable-shop` set exists; broaden coverage before claiming rule completeness).
- Final architecture/threat model and setup docs updated to match code.
- Reproducible demo repository and clean-environment run-through.
- Short public video, project images, and submission copy.
- Screenshots/logs that substantiate functionality and any measured claims.

Do not publish API keys, real customer code, or fabricated demo results.
