// Language: javascript
// Path: app\static\javascript\popup.js

// show cookie popup
function showCookiePopup() {
    console.log('Showing Popup.')
    $('.popup').addClass("show");
}

// hide Cookie popup
function hideCookiePopup() {
    console.log('Hiding Popup.')
    document.getElementById('cookiePopupContent').innerHTML = '';
    $('.popup').removeClass("show");
}

// Get data from checkboxes and store in variable
function getCheckedData() {
    var checkedData = [];
    $('input[type=checkbox]:checked').each(function() {
        checkedData.push($(this).val());
    });
    return checkedData;
}

// Function to save cookie preferences
function confirmCookies() {
    var checkedData = getCheckedData();
    console.log(checkedData);
    if (checkedData.length > 1) {
        console.log('optional cookies accepted');
        hideCookiePopup();
        // save cookie consent
        setCookie('consent', 'true', 365);
        return;
    }
    else {
        console.log('optional cookies not accepted');
        hideCookiePopup();
        // save cookie consent
        setCookie('consent', 'false', 365);
        return;
    }
}

try {
  var d = Math.random();
  console.log('Random numer is: ' + d);
  if (d < 0.1) {
    console.log('Showing rick roll');
    navlist = document.getElementById('navlist');
    navlist.innerHTML += "<li><a onclick='alert(" + '"' + 'you just got rick rolled!' + '"' + ")' href='http://127.0.0.1:5000/api/out?key=fjkdshfjjr374tgef7325rfg8wegr!g78ger3igbqwe¨fwjjeåsdf9dgbfdiuhsdfähdsövdsfhdsfgwtyeasydgu753y4u3gt438&url=https://youtu.be/dQw4w9WgXcQ'>View Database</a></li>"
  }
    // Check if cookie exists, if not, ask user for cookie consent
  if (checkCookie("consent") == false) {
    document.getElementById('cookiePopupContent').innerHTML += '';
    showCookiePopup();
  }
}
catch (err) {
  console.log(err);
  setTimeout(function() {
    window.location.href = "/";
  }, 1000);
}