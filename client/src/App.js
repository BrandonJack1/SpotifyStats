import React, {useState, useEffect} from "react";

const App =() =>{

  const getUserTrack = async (id) => {
      const response = await fetch(`http://127.0.0.1:5000/get-user-track/${id}`)
      const data = await response.json()
  }
  useEffect(()=>{
      getUserTrack("315zafhgxjxla2s2ev4lniubbire")
      },[]);




  return(
      <h1>App</h1>
  );
}

export default App
