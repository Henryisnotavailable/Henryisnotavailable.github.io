# Clickfix

A clickfix attack, is a relatively new type of attack which exploits a user's trust in platforms and CAPTCHA's that they regularly see, day-to-day. Coined by [Proofpoint](https://www.proofpoint.com/uk/blog/threat-insight/clipboard-compromise-powershell-self-pwn) in 2024, it's prevalence has only increased.

Take the captcha below.

![Captcha](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/refs/heads/main/assets/images/Screenshot%202026-06-30%20134016.png)

A Captcha (or Turnstile as Cloudflare calls their implementation) has likely been seen by any user of the internet in the last 10 years. Whilst unaware of it, users have been conditioned to inherently trust this page because they see it so often, especially on sites that they trust.

According to [Builtwith](https://trends.builtwith.com/websitelist/Cloudflare-Turnstile), approximately 650,000 of the World's largest websites make use of Cloudflare's Turnstile (as of the time of writing).

We have all seen Captcha's like this, and we naturally do as they tell us, to gain access to the website they are protecting. After all, how else can we prove that we're not a robot? 

The issue with this, is what if that inherent trust gets abused by malicious actors. When a user accesses a page protected by Cloudflare, how far will they go to prove that they're not an automaton? I know that I will click photos, slide puzzle pieces and rotate animals.

![Animal Captcha](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/refs/heads/main/assets/images/F2jXAgjWkAAEuzT.png)

## Taking it one step too far

![Dont steal a car](https://github.com/Henryisnotavailable/Henryisnotavailable.github.io/blob/main/assets/images/dontstealacar.jpg?raw=true)

You wouldn't run a command from a stranager on the internet.
You wouldn't download a virus.
If Cloudflare's captcha told you to run a command, to prove you're not a robot, would you? 

Some users might question the sudden change in methods and the suspicious actions it's asking them to commit. Some users might really need to access the site, and will blindly follow the instructions on screen. 

Nevertheless, some users, inevitably, will fall for a clickfix attack the anatomy of such an attack is below.

## How clickfix attacks are constructed

The core of a clickfix attack is the following JavaScript. Variations of it have been seen, using older deprecated methods like `document.execCommand("copy")`
```JavaScript
function updateClipboard(newClip) {
  navigator.clipboard.writeText(newClip).then(
    () => {
      /* clipboard successfully set */
    },
    () => {
      /* clipboard write failed */
    },
  );
}
```

