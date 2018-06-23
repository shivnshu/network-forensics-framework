$(document).ready(function(){

    window.FileSelected = function(e)
    {
        file = document.getElementById('customFile').files[document.getElementById('customFile').files.length - 1];
        document.getElementById('customFileLabel').innerHTML = file.name;
    }

    var advAnalysis = function() {
        //alert(this.value);
        location.href = this.value + '.html';
    }
 
    var btnsAnalyse = document.getElementsByClassName("btn-analyse");
    for (var i = 0; i < btnsAnalyse.length; i++) {
        btnsAnalyse[i].addEventListener('click', advAnalysis, false);
    }

});
