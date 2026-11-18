import { initializeApp } from 'firebase/app';
import { getFirestore, addDoc, collection } from 'firebase/firestore';

const app = initializeApp({ projectId: 'fixture-not-real' });
const db = getFirestore(app);

export function saveNote(text) {
  return addDoc(collection(db, 'notes'), { text });
}
