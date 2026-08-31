import React from 'react';


function Modal({ title, content, onClose }) {
  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.modal} onClick={e => e.stopPropagation()}>
        <h2>{title}</h2>
        <div style={styles.content}>
          {content}
        </div>
                <button style={styles.closeBtn} onClick={onClose}>Fechar</button>
      </div>
    </div>
  );
}

const styles = {
  overlay: {
    position: 'fixed',
    top: 0, left: 0, right: 0, bottom: 0,
    backgroundColor: 'rgba(0,0,0,0.5)',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 1000,
  },
  modal: {
    backgroundColor: 'white',
    width: '90%',
    maxWidth: 600,
    maxHeight: '80vh',
    padding: 20,
    borderRadius: 8,
    boxSizing: 'border-box',
    display: 'flex',
    flexDirection: 'column',
  },
  content: {
    overflowY: 'auto',
    flexGrow: 1,
    marginBottom: 20,
  },
  closeBtn: {
    alignSelf: 'flex-end',
    padding: '8px 16px',
    cursor: 'pointer',
  },
};

export default Modal;
