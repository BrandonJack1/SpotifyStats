import React, {useState} from "react";
import {json, useNavigate} from "react-router-dom";


function SignInButton(){

    const nav = useNavigate()
    const [data, setData] = useState(String)
    const getData = async () => {
        await fetch('http://127.0.0.1:5000/home', {method: 'GET',})
            .then((response) => response.json())
            .then((json) => {
                console.log(json)
                setData(json)
            })


        console.log(data.result)
        if (data.result === "sign-in"){
                window.location.replace(data.url)
            }
        else if (data.result === 'redirect'){
            //nav('/home')
        }
        else if (data.result === 'successful'){
            //nav('/home')
        }
        console.log("Here")
    }

    //console.log(JSON.parse(data))
    //const result = JSON.parse(data)


    return(
        <div classname = "App">
        <button onClick={getData}>
            Sign in
        </button>

        </div>
    )




}
export default SignInButton