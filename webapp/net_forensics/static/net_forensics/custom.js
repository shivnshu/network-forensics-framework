$(document).ready(function(){

    window.FileSelected = function(e)
    {
        file = document.getElementById('customFile').files[document.getElementById('customFile').files.length - 1];
        document.getElementById('customFileLabel').innerHTML = file.name;
    }

        /* Set the width of the side navigation to 250px */
    window.openNav = function() {
        document.getElementById("mySidenav").style.width = "350px";
    }

    /* Set the width of the side navigation to 0 */
    window.closeNav = function() {
        document.getElementById("mySidenav").style.width = "0";
    } 

});
