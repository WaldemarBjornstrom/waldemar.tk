function checkBrowser() {
    if (navigator.userAgent.indexOf("Edge") != -1 ) {
        console.log('Edge')
        return "edge" // Maybe add a "Recommend you to switch browsers" promt?
      }
    // CHROME
    else if (navigator.userAgent.indexOf("Chrome") != -1 ) {
        console.log('Chrome')
        return "modern" // Hopefully...
      }
      // FIREFOX
      else if (navigator.userAgent.indexOf("Firefox") != -1 ) {
        console.log('Firefox')
        return "modern" // Hopefully...
      }
      // INTERNET EXPLORER
      else if (navigator.userAgent.indexOf("MSIE") != -1 ) {
        console.log('MSIE')
        return "old" // No one should use MSIE
      }
      // SAFARI
      else if (navigator.userAgent.indexOf("Safari") != -1 ) {
        console.log('Safari')
        return "apple"
      }
      // OPERA
      else if (navigator.userAgent.indexOf("Opera") != -1 ) {
        console.log('Opera')
        return "modern" // Still, Hopfully
      }
      // YANDEX BROWSER
      else if (navigator.userAgent.indexOf("YaBrowser") != -1 ) {
        console.log('YaBrowser')
        return "unconventional"
      }
      // OTHERS
      else {
        console.log('Other')
        return "unconventional"
      }
}

function createPopup() {
    console.log('Creating Popup based on browser')
    browser = checkBrowser();
    console.log('Which is:')
    setCookie("browser", browser)
    console.log(browser)
    var div = document.getElementById('browserPopupContent');

    if (browser == "old") {
        extracontent ="<p>You are using an older browser. This page is most definitly not showing up as expected. Please consider updating your browser.</p>"
    }
    else if (browser == "unconventional") {
        extracontent ="<p>You are using a browser that we haven't tested on this site. So the page is probably not showing up as we intended. Continue at your own risk, or go download <a href='https://www.google.com/intl/sv/chrome/'>Chrome</a> or something.</p>"
    }
    else if (browser == "apple") {
        extracontent ="<p>You have no idea how many use old browsers! Thank you for not being one of them!</p><p>You may wonder how i know this, But i know that you are there, staring at your fancy Apple device. It probably cost you a fortune too.</p>"
    }
    else if (browser == "modern") {
        extracontent ="<p>You have no idea how many use old browsers! Thank you for not being one of them!</p>"
    }
    else if (browser == "edge") {
        extracontent == "<p>You have no idea how many use old browsers! Thank you for not being one of them! (But you shouldn't use edge)"
    }
    else {
        extracontent = "<p>Hmm, somthing went wrong on our end, or you have a really unconventional browser... Sorry!</p>"
    }
    console.log('Fetched browser and created text:')
    console.log(extracontent)
    div.innerHTML += extracontent;
    showPopup();
}

function showPopup() {
    console.log('Showing Popup.')
    $('.popup').addClass("show");
    setCookie("jgCVBi", 1, 14)
}

function hidePopup() {
    console.log('Hiding Popup.')
    $('.popup').removeClass("show");
}

if (checkCookie("jgCVBi") == false) {
  setTimeout(function() {
      createPopup();
      setTimeout(function() {
          hidePopup();
      }, 60000)
  }, 1000);
}
