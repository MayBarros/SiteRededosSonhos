import React, { useState } from "react";
import "../styles/Dashboard.css";

function Dashboard() {
  const user = JSON.parse(localStorage.getItem("user"));
  const [chatUser, setChatUser] = useState(null);
  const [posts, setPosts] = useState([
    {
      id: 1,
      name: "Maria Silva",
      text: "O meu sonho é expandir minha pequena produção de doces artesanais para uma loja física onde eu possa ensinar outras mulheres da comunidade. 🧁✨",
      value: "R$ 5.000",
      image: "https://images.unsplash.com/photo-1488477181946-6428a0291777?auto=format&fit=crop&w=800&q=80"
    }
  ]);

  const [newPost, setNewPost] = useState({ text: "", value: "", image: null, preview: null });

  const handleImage = (e) => {
    const file = e.target.files[0];
    if (file) {
      const preview = URL.createObjectURL(file);
      setNewPost({ ...newPost, image: file, preview: preview });
    }
  };

  const handlePost = () => {
    if (!newPost.text || !newPost.value) return alert("Por favor, preencha os campos.");
    const post = {
      id: Date.now(),
      name: user?.nome || "Você",
      text: newPost.text,
      value: `R$ ${newPost.value}`,
      image: newPost.preview
    };
    setPosts([...posts, post]);
    setNewPost({ text: "", value: "", image: null, preview: null });
  };

  return (
    <div className="dashboard">
      <aside className="sidebar">
        <div style={{textAlign: 'center'}}>
          <img src="https://i.pravatar.cc/150?u=9" alt="avatar" style={{width: 100, borderRadius: '50%', border: '4px solid #dbeafe'}} />
          <h3 style={{marginTop: 15}}>{user?.nome || "Usuário"}</h3>
          <p style={{color: '#64748b', fontSize: '0.9rem'}}>Me ajude realizar meu sonho</p>
        </div>
        <div style={{marginTop: 30, display: 'flex', flexDirection: 'column', gap: 10}}>
          <button
             className="btn"
             style={{background: '#f1f5f9'}}
             onClick={() => window.location.href = "/perfil"}
>
                Meu Perfil
          </button>
          <button className="btn" style={{background: '#f1f5f9'}}>Buscar sonhos</button>
          <button className="btn" style={{color: '#ef4444', background: '#fef2f2'}} onClick={() => window.location.href='/login'}>Sair</button>
        </div>
      </aside>

      <main className="feed">
        <h2 style={{color: '#1e3a8a'}}>Sonhos Compartilhados</h2>
        
        {/* FEED DE POSTS (EM CIMA) */}
        <div className="posts-container">
          {posts.map(post => (
            <article key={post.id} className="post">
              {post.image && <img src={post.image} alt="Imagem do sonho" className="post-image" />}
              <div className="post-content">
                <div className="post-header">
                  <span className="post-name">{post.name}</span>
                  <span className="post-value-tag">{post.value}</span>
                </div>
                <p className="post-description">{post.text}</p>
                <button className="btn" style={{marginTop: 20, background: '#eff6ff', color: '#2563eb', width: '100%'}} onClick={() => setChatUser(post.name)}>
                  💬 Apoie este sonho
                </button>
              </div>
            </article>
          ))}
        </div>

        {/* ÁREA DE PUBLICAÇÃO (EMBAIXO) */}
        <div className="create-post">
          <h4 style={{color: '#2563eb'}}>O que você está planejando?</h4>
          
          <div style={{display: 'flex', gap: 10, marginTop: 10}}>
            <input 
              type="text" 
              placeholder="Valor necessário (Ex: 1.500)" 
              style={{flex: 1, padding: 12, borderRadius: 10, border: '1px solid #e2e8f0'}}
              value={newPost.value}
              onChange={(e) => setNewPost({...newPost, value: e.target.value})}
            />
            <label className="btn" style={{background: '#dbeafe', color: '#1e4ed8', cursor: 'pointer'}}>
              📷 Foto
              <input type="file" hidden accept="image/*" onChange={handleImage} />
            </label>
          </div>

          <textarea 
            placeholder="Conte a história por trás do seu sonho..."
            value={newPost.text}
            onChange={(e) => setNewPost({...newPost, text: e.target.value})}
          />

          {newPost.preview && (
            <div className="preview-wrapper">
              <button className="btn-remove" onClick={() => setNewPost({...newPost, preview: null, image: null})}>
                Excluir Foto X
              </button>
              <img src={newPost.preview} className="preview-img" alt="Preview" />
            </div>
          )}

          <button className="btn btn-primary" onClick={handlePost}>Publicar meu sonho</button>
        </div>
      </main>

      <aside className="chat">
        <h3 style={{color: '#1e3a8a'}}>Mensagens</h3>
        <div style={{height: '80%', background: '#f8fafc', borderRadius: 12, margin: '15px 0', padding: 15}}>
          {chatUser ? <p>Conversando com <strong>{chatUser}</strong></p> : <p style={{color: '#94a3b8'}}>Selecione um sonho.</p>}
        </div>
        <input type="text" placeholder="Escreva..." style={{width: '100%', padding: 10, borderRadius: 8, border: '1px solid #e2e8f0'}} disabled={!chatUser} />
      </aside>
    </div>
  );
}

export default Dashboard;