# Third-party notices

STRIDE Threat Modeler has **no runtime or build dependencies**. All code in this repository was
written for this project.

## Microsoft Threat Modeling Tool compatibility

This project is independent and is not affiliated with or endorsed by Microsoft. "Microsoft Threat
Modeling Tool" is a trademark of Microsoft Corporation.

- The built-in template reuses MTMT's element type identifiers, property names and values, and
  threat rule expressions. It does this so that templates and rules interoperate. Threat titles,
  descriptions and mitigations are original text.
- No Microsoft binaries, templates, icons or images are included. Users can import `.tb7` templates
  they obtained themselves, including those Microsoft publishes at
  <https://github.com/microsoft/threat-modeling-templates>.
- `.localdev/Microsoft_ThreatModellingTool.md` describes MTMT's behaviour. It was produced by static
  analysis of the publicly distributed tool for interoperability purposes, and it is not part of the
  published repository.

## Fonts

The UI asks for the system fonts "Virgil"/"Excalifont" when they are installed, and otherwise falls
back to the platform's handwriting or system fonts. No font files are bundled.
