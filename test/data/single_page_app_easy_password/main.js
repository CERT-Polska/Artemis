function getContent(fragmentId, callback){

  var pages = {
    home: "Test home",
    about: "Test about",
    login: "Test login",
    contact: "Test contact",
  };

  callback(pages[fragmentId]);
}



function loadContent(){

  var contentDiv = document.getElementById("app"),
      fragmentId = location.hash.substr(1);

  getContent(fragmentId, function (content) {
    contentDiv.innerHTML = content;
  });

}

if(!location.hash) {
  location.hash = "#home";
}

loadContent();

window.addEventListener("hashchange", loadContent)

const loginForm = document.getElementById("login-form");
const loginButton = document.getElementById("login-form-submit");
const loginErrorMsg = document.getElementById("login-error-msg");

loginButton.addEventListener("click", (e) => {
    e.preventDefault();
    const username = loginForm.username.value;
    const password = loginForm.password.value;
    if (username === "admin" && password === "admin1") {
        alert("Logged in successfully");
    } else {
        loginErrorMsg.style.visibility="visible"
    }
})
