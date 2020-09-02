const btnSend = document.querySelectorAll('.btn-enviar')

if(btnSend){
    const btnArray = Array.from(btnSend);
    btnArray.forEach((btn) => {
        btn.addEventListener('click', (e) => {
            if(!confirm('¿Estas seguro de querer enviar el escaneo a su correo?')){
                e.preventDefault();
            }

        })
    })
}