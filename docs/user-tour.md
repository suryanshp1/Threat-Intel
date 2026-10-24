# User tour

## Plan and behavior

The tour introduces the existing investigation workflow without requiring imported data or an administrator role:

1. Offer a dismissible invitation after the workspace identity loads.
2. Visit Overview, Vulnerabilities, Threat actors, Supply chain, KB lookup, SBOM & VEX, Data sources, and API & integrations.
3. Explain what to do on each screen and the limits of the underlying evidence.
4. Support Back, Next, Finish, close, and Escape; return to the starting URL, including search parameters and fragment, when finished or exited.
5. Keep a permanent **User tour** header control for replay on desktop and mobile.

Starting the tour navigates between real screens. It does not submit searches, run ingestion, analyze an SBOM, import VEX, or change server data. Existing page queries can run normally. Start it after saving any in-progress form input, because changing screens unmounts those forms. The original URL is restored; form state and scroll position are not restored.

The invitation dismissal is stored in browser localStorage as `sentinel-tour-v1=seen` when dismissed or started. This preference is shared by people using the same browser profile on the same origin; it is not an account setting. If browser storage is unavailable, the tour still works and the invitation may return on reload.

## Implementation and verification

`frontend/src/tour-data.ts` holds the ordered content and resilient preference helpers. `tour.tsx` uses a native modal dialog for keyboard focus containment and Escape handling. The dialog focuses each new step heading, prevents background scrolling, and uses the app’s theme variables. The header entry remains available at narrow widths with an accessible icon label.

Run `npm run test:frontend` for preference regression coverage and `npm run build` for TypeScript and production bundling. Browser checks should cover all eight routes, Back, Finish, Escape, original URL restoration, focus containment and return, invitation dismissal across reloads, replay, and narrow/light/dark layouts. Browser API fixtures must remain separate from the real catalog.
