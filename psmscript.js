let hibpTimeout;

function rotate(header) {
  let chevron = header.querySelector(".chevron");
  let content = header.nextElementSibling;

  if (content.style.maxHeight && content.style.maxHeight !== "0px") {
    content.style.maxHeight = "0px";
    chevron.style.transform = "rotate(0deg)";
  } else {
    content.style.maxHeight = content.scrollHeight + "px";
    chevron.style.transform = "rotate(90deg)";
  }
}

function checkPassword() {
  document
    .getElementById("hide-password")
    .addEventListener("change", function () {
      let passwordField = document.getElementById("password");
      if (this.checked) {
        passwordField.type = "text";
      } else {
        passwordField.type = "password";
      }
    });

  let password = document.getElementById("password").value;
  let entropy = calculateEntropy(password);
  let strength = getStrength(password, entropy);

  document.getElementById("entropy").innerText = `Entropy: ${entropy.toFixed(
    2
  )} bits`;
  document.getElementById("feedback").innerHTML = strength.feedback;
  let charLen = document.getElementById("char-count");
  charLen.innerText = "Characters : " + password.length;
  if (password.length >= 10) {
    charLen.classList.add("active");
  } else {
    charLen.classList.remove("active");
  }

  updateStrengthBar(strength.score);

  document.getElementById("password").addEventListener("input", function () {
    document.getElementById("hibp-feedback").innerHTML = "...";
    if (document.getElementById("auto-check").checked) {
      clearTimeout(hibpTimeout);
      hibpTimeout = setTimeout(checkHaveIBeenPwned, 1000);
    }
  });
  if (document.getElementById("auto-check").checked && password.length > 0) {
    clearTimeout(hibpTimeout);
    hibpTimeout = setTimeout(checkHaveIBeenPwned, 1000);
  }
}

function calculateEntropy(password) {
  let length = password.length;
  let charSetSize = CharacterSets(password);
  let entropy = Math.log2(Math.pow(charSetSize, length));
  return entropy;
}

function CharacterSets(password) {
  let size = 0;
  let lowC = document.getElementById("lowercase");
  let uppC = document.getElementById("uppercase");
  let numb = document.getElementById("numbers");
  let spec = document.getElementById("special");

  lowC.classList.remove("active");
  uppC.classList.remove("active");
  numb.classList.remove("active");
  spec.classList.remove("active");

  if (/[a-z]/.test(password)) {
    size += 26;
    lowC.classList.add("active");
  }
  if (/[A-Z]/.test(password)) {
    size += 26;
    uppC.classList.add("active");
  }
  if (/[0-9]/.test(password)) {
    size += 10;
    numb.classList.add("active");
  }
  if (/[\W_]/.test(password)) {
    size += 33;
    spec.classList.add("active");
  }
  return size;
}

function getStrength(password, entropy) {
  let score = 0;
  let feedback = [];

  if (entropy == 0) {
    score = 0;
    feedback.push("Password Strength: ...");
    return { score, feedback };
  }
  if (entropy > 120)
    (score = 5), feedback.push("Password Strength: Very Strong ");
  else if (entropy > 90)
    (score = 4), feedback.push("Password Strength: Strong");
  else if (entropy > 60)
    (score = 3), feedback.push("Password Strength: Moderate");
  else if (entropy > 30) (score = 2), feedback.push("Password Strength: Weak");
  else if (entropy > 0)
    (score = 1), feedback.push("Password Strength: Very Weak");

  return { score, feedback: feedback.join("<br>") };
}

function updateStrengthBar(score) {
  let fill = document.getElementById("strength-fill");
  let widths = ["0%", "20%", "40%", "60%", "80%", "100%"];
  let classes = [
    "empty",
    "veryweak",
    "weak",
    "moderate",
    "strong",
    "verystrong",
  ];

  fill.style.width = widths[score];
  fill.className = `strength-fill ${classes[score]}`;
}

async function checkHaveIBeenPwned() {
  let breached = 0;
  let breachCount = 0;
  let password = document.getElementById("password").value;
  let hibpFeedback = document.getElementById("hibp-feedback");
  let strengthFeedback = document.getElementById("feedback");
  let strengthFill = document.getElementById("strength-fill");
  let button = document.getElementById("hibp-check-btn");

  if (password.length === 0) {
    return;
  }

  button.disabled = true;
  hibpFeedback.innerHTML = "Checking...";

  let sha1Hash = await sha1(password);
  let prefix = sha1Hash.substring(0, 5);
  let suffix = sha1Hash.substring(5).toUpperCase();

  try {
    let response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`
    );
    let text = await response.text();
    let found = text.split("\n").find((line) => line.startsWith(suffix));

    if (found) {
      breached = 1;
      breachCount = parseInt(found.split(":")[1]);
    } else {
      breached = 0;
      breachCount = 0;
    }
  } catch (error) {
    hibpFeedback.innerHTML =
      "<span style='color: orange;'>Error checking HIBP.</span>";
  }

  if (breached == 1) {
    hibpFeedback.innerHTML =
      "<span style='color: red;'>This password has been breached <b>" +
      breachCount +
      "</b> times!</span>";
    strengthFeedback.innerHTML = "<span style ='color: red;'>Breached Password";
    strengthFill.style.width = "100%";
    strengthFill.className = "strength-fill breached";
  } else {
    hibpFeedback.innerHTML =
      "<span style='color: green;'>This password has been breached <b>" +
      breachCount +
      "</b> times!</span>";
  }
  button.disabled = false;
}

// SHA-1 Hash Function
async function sha1(str) {
  const buffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}
