import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Home from "./pages/home.js";
import Welcome from "./pages/welcome";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Welcome />}>
          <Route path ="/home" element={<Home />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);