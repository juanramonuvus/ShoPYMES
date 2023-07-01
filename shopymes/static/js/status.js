/*
  function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
      var cookies = document.cookie.split(';');
      for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i].trim();
        if (cookie.substring(0, name.length + 1) === (name + '=')) {
          cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
          break;
        }
      }
    }
    return cookieValue;
  }
  
  function notification(type,message){
    var notification_div = document.getElementById('notification_div')
  
    notification_div.getElementsByClassName('right-not')[0].getElementsByTagName('div')[0].className = "notification-title orangetext";
    document.getElementById('notification_div').className = "";
    document.getElementById('notification_div').offsetTop;
    if(type == 'correct'){
      document.getElementById('notification_div').className = "notification correct";
      notification_div.getElementsByClassName('right-not')[0].getElementsByTagName('div')[0].className = "notification-title greentext";
      notification_div.getElementsByClassName('right-not')[0].getElementsByTagName('div')[0].innerText = "Correcto";
      document.getElementsByClassName('notification-logo')[0].src = '/static/img/correct-not.svg';
    }
    else if(type == 'error'){
      document.getElementById('notification_div').className = "notification error";
      notification_div.getElementsByClassName('right-not')[0].getElementsByTagName('div')[0].className = "notification-title redtext";
      notification_div.getElementsByClassName('right-not')[0].getElementsByTagName('div')[0].innerText = "Error";
      document.getElementsByClassName('notification-logo')[0].src = '/static/img/excl-not.svg';
    }else{
      document.getElementById('notification_div').className = "notification info";
      notification_div.getElementsByClassName('right-not')[0].getElementsByTagName('div')[0].className = "notification-title orangetext";
      notification_div.getElementsByClassName('right-not')[0].getElementsByTagName('div')[0].innerText = "Info";
      document.getElementsByClassName('notification-logo')[0].src = '/static/img/info-not.svg';
    }
  
    document.getElementById('notification-info').innerText = message;
    notification_div.style.display = 'block';
  
  }
  
  function checkStatus(){
      var jqxhr = $.get( "/api/status").done(function( data ) {
          headerStatus = document.getElementById("header-status")
          headerStatus.innerHTML = "Estado: " + data.status + " | Host: " + data.host;
          headerStatus.style.backgroundColor = data.color;
  
          if(data.notf != '' & data.notf != undefined){
            console.log(data.notf)
            notification(data.notf_type,data.notf)
          }
  
          assetsNum = document.getElementById("assetsnum")
          alertsNum = document.getElementById("alertsnum")
          incidentsNum = document.getElementById("incidentsnum")
  
          try{
            assetsNum.innerHTML = data.assets
            alertsNum.innerHTML = data.alerts
            incidentsNum.innerHTML = data.incidents
  
          }catch(e){
            
          }
  
  
          logs = "<tr><th>Fecha y hora</th><th>Evento</th></tr>"
  
          
          
          for(var i= 0; i < data.logs.length; i++){
            logs += '<tr class="tr-log"><td class="td-log">'+data.logs[i]['date']+'</td><td class="td-log">'+data.logs[i]['description']+'</td></tr>'
            
          }
  
          $(".events").html(logs);
        
        });
  }
  
  
  const interval = setInterval(checkStatus,3000);
  
  var searchid = 0;
  
  */
  tds = document.getElementsByTagName("td")
  
  function validateAux(message,callback){
    document.getElementById("confirmation-message").innerHTML = message;
    document.getElementById("popup").style.width = '400px';
    document.getElementById("popup-message").style.minHeight = '120px';
    document.getElementById("popup").style.minHeight = '200px';
    document.getElementById("popup-buttons").innerHTML = '<button id="cancel-button" class="form-button greenbg white">Cancelar</button> <button id="confirm-button" class="form-button greenbg white">Continuar</button>';
  
    document.getElementById("popup-overlay").style.display = 'block';
    
    var confirmButton = document.getElementById("confirm-button"); 
    var cancelButton = document.getElementById("cancel-button"); 
  
    confirmButton.onclick = function() { callback(true); };
    cancelButton.onclick = function() { callback(false); };
  }
  
  
  function validateLink(element,message){
    validateAux(message,function(confirmed){
      if(confirmed){
        window.location.href = element.href;
      }else{
        document.getElementById("popup-overlay").style.display = 'none';
      }
    })
  }

  /*
  function validateForm(element,message){
    validateAux(message,function(confirmed){
      if(confirmed){
        element.form.submit();
      }else{
        document.getElementById("popup-overlay").style.display = 'none';
      }
    })
  }
  
*/
function informationAux(message, callback) {
    document.getElementById("confirmation-title").innerHTML = "Información";
    document.getElementById("confirmation-message").innerHTML = message;
    document.getElementById("popup-message").style.minHeight = '120px';
    document.getElementById("popup").style.width = '550px';
    document.getElementById("popup").style.minHeight = '200px';
    document.getElementById("popup-overlay").style.display = 'block';
    document.getElementById("popup-buttons").innerHTML = '<button id="back-button" class="form-button greenbg white">Aceptar</button>';
    var backButton = document.getElementById("back-button");
    backButton.onclick = function () { callback(true); };
}

function informationBox(element, message, h) {
    informationAux(message, function (confirmed) {
        if (confirmed) {
            document.getElementById("popup-overlay").style.display = 'none';
        }
    })
}


function loadingGenerator(element,message){
  document.getElementById("confirmation-title").innerHTML = "Espere";
  document.getElementById("confirmation-message").innerHTML = message;
  document.getElementById("popup-message").style.minHeight = '0px';
  document.getElementById("popup").innerHTML += '<div><img class='+'"loading"'+' src="/static/img/loading.svg"' + '" width="50"> </div>';
  document.getElementById("popup-buttons").innerHTML = '';
  document.getElementById("popup").style.width = '400px';
  document.getElementById("popup").style.minHeight = '200px';
  document.getElementById("popup-overlay").style.display = 'block';
  
}

function validateGenerator(element,message){
  n = parseInt(document.getElementById("n-assets").innerText)
  if(n == 0){
    document.getElementById("notification-info").innerText ="Debe seleccionar al menos un activo de la lista.";
    document.getElementById("notification_div").style.display = "block";
  }else{
    loadingGenerator(element,message);
    element.form.submit();
  }
}
  
  
 
  var checked_ids = new Set(); 
  
  function assetCheck(element){
    n = parseInt(document.getElementById("n-assets").innerText)
    if(element.checked){
      document.getElementById("n-assets").innerText = n + 1
      checked_ids.add(element.value);
      element.parentElement.parentElement.style.backgroundColor = '#51cbee66';
    }else{
      document.getElementById("n-assets").innerText = n - 1
      element.parentElement.parentElement.style.backgroundColor = 'white';
      checked_ids.delete(element.value);
    }
  
  }
  
/*  
  function filterAssets(){
    var jqxhr = $.post( "/api/filterassets",{'nombre':document.getElementById("name").value.toUpperCase(),'ip':document.getElementById("ip").value.toUpperCase(),'mac':document.getElementById("mac").value.toUpperCase(),'checked': Array.from(checked_ids)}).done(function( data ) {
      document.getElementsByTagName('tbody')[1].innerHTML = data['inner'];
      });
  }
  

*/