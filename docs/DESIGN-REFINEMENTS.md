# Anazori interface refinements

The Organising Studio now shares an ivory, deep violet and teal palette with its sign-in page. Native disclosure components group the sidebar navigation, website settings, staff editor, permission groups, media upload and integrations. Click a heading to reveal its tools. Editing an existing staff account opens its editor automatically; settings jump links reveal their destination. Validation opens any collapsed ancestor of a required field before focusing it.

The website uses the existing Monument Extended files for its principal headings, Anazori wordmarks and event names. The Culture typography and the sponsor invitation bento retain their established character. The font files remain in their original asset folder.

The word ribbon is now a decorative energy conduit; its cycle duration is adjustable in Website settings → Hero & energy beam. Original SVG corner tracery frames event cards, team portraits and a 16:9 official-film space. Gallery captions, image alt text and lightbox descriptions omit the old edition labels; original CMS year metadata remains available to organisers. The event list displays every published event without category or search controls.

Sponsor displays surround each logo with moving orbital paths and a subtle vertical float. Both sample previews and published sponsor records use the treatment. The samples are still explicitly labelled as unconfirmed. These animations use transforms and pause outside the viewport or when motion is paused; reduced-motion preferences stop them.

Entry sound runs only on the home page and only once per browser-tab visit. It follows the Studio's existing sound-enabled setting. Browsers that block autoplay defer playback to the first permitted tap or Enter/Space gesture. Reloads, returning from another page and visibility changes do not restart sound. Sound stops when the tab is hidden or when the official video starts with sound. The background hero film remains silent.

To add the official film: upload it through **Media library**, then open **Website settings → Our spirit & video** and choose **Introduction video**, or enter a YouTube/Vimeo/MP4 link. Save that settings group. The same frame automatically displays the published film and its player controls.

Design research included [LVCIDIA's immersive art presentation](https://www.awwwards.com/sites/lvcidia), [Motley Crowd's event navigation](https://www.awwwards.com/inspiration/motley-crowd-immersive-events), [Riot's visual clarity approach](https://www.leagueoflegends.com/en-us/news/dev/clarity-in-league/) and [Monument Extended's foundry page](https://pangrampangram.com/products/Monument-extended). The borders and graphics in this project are original code/SVG artwork.

Validation: `npm run build`, `npm run test:refinements`, `npm run test:cms`, `node tests/studio-finance-browser.mjs`, `npm run test:browser` and `npm run test:retro`. The focused suite checks 320–1440px layouts, real film settings, public labels, native keyboard accordions, expanded-form accessibility, sponsor motion, one-shot audio and reduced motion against a disposable database. Screenshots and accessibility results are in `.local/refinements`.
