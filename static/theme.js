function switchTheme() {
  var element = document.body;
  var currentTheme = element.dataset.bsTheme;
  var newTheme = currentTheme === "light" ? "dark" : "light";
  element.dataset.bsTheme = newTheme;
  localStorage.setItem('theme', newTheme);
  updateToggleSwitch(newTheme);
}

function updateToggleSwitch(theme) {
  var toggleSwitch = document.getElementById('theme-switch');
  toggleSwitch.checked = theme === 'dark';
}

function loadTheme() {
  var savedTheme = localStorage.getItem('theme') || 'dark';
  document.body.dataset.bsTheme = savedTheme;
  updateToggleSwitch(savedTheme);
}

// Call loadTheme when the page loads
document.addEventListener('DOMContentLoaded', loadTheme);
