$(document).ready(function(){

    window.FileSelected = function(e)
    {
        file = document.getElementById('customFile').files[document.getElementById('customFile').files.length - 1];
        document.getElementById('customFileLabel').innerHTML = file.name;
    }

});
