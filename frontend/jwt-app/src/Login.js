import React from "react";
import { GoogleLogin } from "react-google-login";
import Axios from "axios";

const config = {
  headers: {
    "Content-Type": "application/json; charset=utf-8",
  },
};

const responseGoogle = async (response) => {
  console.log(1, response);
  let jwtToken = await Axios.post(
    "http://localhost:8080/api/oauth/jwt/google",
    JSON.stringify(response),
    config
  );
  if (jwtToken.status === 200) {
    // console.log(2, jwtToken.data);
    console.log(jwtToken);
    localStorage.removeItem("jwtToken");
    localStorage.setItem("jwtToken", jwtToken.data[0]);
    localStorage.setItem("refreshToken", jwtToken.data[1]);
  }
};

const Login = () => {
  return (
    <GoogleLogin
      clientId="xxxxxxx"
      buttonText="Google 로그인"
      onSuccess={responseGoogle}
      onFailure={responseGoogle}
      cookiePolicy={"single_host_origin"}
    />
  );
};

export default Login;