import React from 'react';
import { useLocation, Outlet } from 'react-router-dom';
import Header from './Header'; 
import Footer from './Footer'; 

function Layout() {
  const location = useLocation();
  const rotasSemHeader = ['/quem-somos', '/comoFunciona'];
  const esconderHeader = rotasSemHeader.includes(location.pathname);

  return (
    <div className="app">
      {!esconderHeader && <Header />}
      <main>
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}

export default Layout;

