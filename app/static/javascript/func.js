function setCookie(cname, cvalue, exdays) {
    const d = new Date();
    d.setTime(d.getTime() + (exdays*24*60*60*1000));
    let expires = "expires="+ d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
}

function getCookie(cname) {
    let name = cname + "=";
    let decodedCookie = decodeURIComponent(document.cookie);
    let ca = decodedCookie.split(';');
    for(let i = 0; i <ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) == ' ') {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
}

function checkCookie(cname) {
    let cookie = getCookie(cname);
    if (cookie != "") {
      return true
    } else {
      return false
    }
}

function parseJSONfromURL(url) {
  var request = new XMLHttpRequest();
  request.open("GET", url, false);
  request.send(null)
  const prsdjson = JSON.parse(request.responseText);
  return prsdjson
}

function forceLower(strInput) {
strInput.value=strInput.value.toLowerCase();
}
