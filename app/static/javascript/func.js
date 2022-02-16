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

function displaycharcount() {
    
  var characterCount = $('#about').val().length + 1,
      current = $('#current'),
      maximum = $('#maximum'),
      theCount = $('#the-count');
    
  current.text(characterCount);
 
  if (characterCount < 300) {
    current.css('color', '#666');
  }
  if (characterCount > 300 && characterCount < 400) {
    current.css('color', '#6d5555');
  }
  if (characterCount > 400 && characterCount < 450) {
    current.css('color', '#793535');
  }
  if (characterCount > 450 && characterCount < 480) {
    current.css('color', '#841c1c');
  }
  if (characterCount > 480 && characterCount < 498) {
    current.css('color', '#8f0001');
  }
  
  if (characterCount >= 500) {
    maximum.css('color', '#8f0001');
    current.css('color', '#8f0001');
    theCount.css('font-weight','bold');
  } else {
    maximum.css('color','#666');
    theCount.css('font-weight','normal');
  }
  
      
};
