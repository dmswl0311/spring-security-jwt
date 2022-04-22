import React, { useState } from "react";
import "./App.css";
import Login from "./Login";
import Axios from "axios";
import axios from "axios";

const config = {
  headers: {
    Authorization: "Bearer " + localStorage.getItem("jwtToken"),
  }
};

function App() {
  const [user, setUser] = useState(null);
  const [img, setImg] = useState(null);

  const getUser = async () => {
    let res = await Axios.get("http://localhost:8080/api/v1/user", 
      {
      headers: {
          Authorization: "Bearer " + localStorage.getItem("jwtToken"),
        }
      }
    );
    console.log("return확인::",res);
    console.log(res.data);
    if(res.data=="access token expired"){
      console.log("토큰이 만료됨. refreshtoken을 보내세요.");
      let res = await Axios.get("http://localhost:8080/api/v1/user", 
      {
      headers: {
          Authorization: "Bearer " + localStorage.getItem("jwtToken"),
          RefreshToken: "Bearer " + localStorage.getItem("refreshToken"),
        }
      }
    );
      console.log("token이 새로 발급되었습니다.");
      localStorage.setItem("jwtToken",res.data);
      res = await Axios.get("http://localhost:8080/api/v1/user", 
      {
      headers: {
          Authorization: "Bearer " + localStorage.getItem("jwtToken"),
        }
      }
    );
    setUser(res.data.nickname);
    setImg(res.data.img_url);
    }else{
      setUser(res.data.nickname);
      setImg(res.data.img_url);
    }
  };

  return (
    <div>
      <Login />
      <h1>user : {user}님 안녕하세요!</h1>
      <img src={img}></img>
      <button onClick={getUser}>유저정보 가져오기</button>
    </div>
  );
}

export default App;