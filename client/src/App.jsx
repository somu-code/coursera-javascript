import { BrowserRouter } from "react-router-dom";
import { Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Signin from "./pages/Signin";
import Signup from "./pages/Signup";
import Home from "./pages/Home";
import PageNotFound from "./pages/PageNotFound";
import AddCourse from "./pages/AddCourse";
import Courses from "./pages/Courses";
import { RecoilRoot, useSetRecoilState } from "recoil";
import { adminState } from "./store/atoms/admin";
import { serverApi } from "./ServerApi";
import { useEffect } from "react";

function App() {
  return (
    <RecoilRoot>
      <BrowserRouter>
        <Navbar />
        <InitAdmin />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/admin/signup" element={<Signup />} />
          <Route path="/admin/signin" element={<Signin />} />
          <Route path="/admin/add-course" element={<AddCourse />} />
          <Route path="/admin/courses" element={<Courses />} />
          <Route path="*" element={<PageNotFound />} />
        </Routes>
      </BrowserRouter>
    </RecoilRoot>
  );
}

function InitAdmin() {
  const setAdmin = useSetRecoilState(adminState);
  useEffect(() => {
    const init = async () => {
      try {
        const response = await fetch(`${serverApi}/admin/profile`, {
          method: "GET",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
        });
        if (response.ok) {
          const jsonData = await response.json();
          setAdmin({
            isLoading: false,
            adminEmail: jsonData.email,
          });
        } else {
          setAdmin({
            isLoading: true,
            adminEmail: null,
          });
        }
      } catch (error) {
        console.error(error);
        setAdmin({
          isLoading: true,
          adminEmail: null,
        });
      }
    };
    init();
  }, []);
  return <></>;
}

export default App;
