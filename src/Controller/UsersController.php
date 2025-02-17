<?php
declare(strict_types=1);

namespace App\Controller;

use Cake\Core\Configure;
use Cake\Http\Exception\UnauthorizedException;
use Firebase\JWT\JWT;

/**
 * Users Controller
 *
 * @property \App\Model\Table\UsersTable $Users
 */
class UsersController extends AppController
{
    /**
     * Initialize controller
     *
     * @return void
     * @throws \Exception
     */
    public function initialize(): void
    {
        parent::initialize();

        // Vérifie que le composant Authentication existe
        if ($this->components()->has('Authentication')) {
            $this->loadComponent('Authentication.Authentication');
            $this->Authentication->allowUnauthenticated(['register', 'login']);
        }
    }

    /**
     * Index method
     *
     * @return \Cake\Http\Response|null|void Renders view
     */
    public function index()
    {
        $query = $this->Users->find();
        $users = $this->paginate($query);

        $this->set(compact('users'));
    }

    /**
     * View method
     *
     * @param string|null $id User id.
     * @return \Cake\Http\Response|null|void Renders view
     * @throws \Cake\Datasource\Exception\RecordNotFoundException When record not found.
     */
    public function view(?string $id = null)
    {
        $user = $this->Users->get($id, contain: []);
        $this->set(compact('user'));
    }

    /**
     * Add method
     *
     * @return \Cake\Http\Response|null|void Redirects on successful add, renders view otherwise.
     */
    public function add()
    {
        $user = $this->Users->newEmptyEntity();
        if ($this->request->is('post')) {
            $user = $this->Users->patchEntity($user, $this->request->getData());
            if ($this->Users->save($user)) {
                $this->Flash->success(__('The user has been saved.'));

                return $this->redirect(['action' => 'index']);
            }
            $this->Flash->error(__('The user could not be saved. Please, try again.'));
        }
        $this->set(compact('user'));
    }

    /**
     * Edit method
     *
     * @param string|null $id User id.
     * @return \Cake\Http\Response|null|void Redirects on successful edit, renders view otherwise.
     * @throws \Cake\Datasource\Exception\RecordNotFoundException When record not found.
     */
    public function edit(?string $id = null)
    {
        $user = $this->Users->get($id, contain: []);
        if ($this->request->is(['patch', 'post', 'put'])) {
            $user = $this->Users->patchEntity($user, $this->request->getData());
            if ($this->Users->save($user)) {
                $this->Flash->success(__('The user has been saved.'));

                return $this->redirect(['action' => 'index']);
            }
            $this->Flash->error(__('The user could not be saved. Please, try again.'));
        }
        $this->set(compact('user'));
    }

    /**
     * Delete method
     *
     * @param string|null $id User id.
     * @return \Cake\Http\Response|null Redirects to index.
     * @throws \Cake\Datasource\Exception\RecordNotFoundException When record not found.
     */
    public function delete(?string $id = null)
    {
        $this->request->allowMethod(['post', 'delete']);
        $user = $this->Users->get($id);
        if ($this->Users->delete($user)) {
            $this->Flash->success(__('The user has been deleted.'));
        } else {
            $this->Flash->error(__('The user could not be deleted. Please, try again.'));
        }

        return $this->redirect(['action' => 'index']);
    }

    public function login()
    {
        $this->request->allowMethod(['post']); // Assure que seule la méthode POST est autorisée

        $user = $this->Users->findByEmail($this->request->getData('email'))->first();

        if (!$user || !password_verify($this->request->getData('password'), $user->password)) {
            throw new UnauthorizedException('Invalid username or password');
        }

        $key = Configure::read('Security.jwt_key');
        $payload = [
            'sub' => $user->id,
            'exp' => time() + 3600,
        ];

        $jwt = JWT::encode($payload, $key, 'HS256');

        return $this->response->withType('application/json')->withStringBody(json_encode(['token' => $jwt]));
    }

    public function register()
    {
        $this->request->allowMethod(['post']); // Seul POST est autorisé

        $user = $this->Users->newEntity($this->request->getData());

        if ($this->Users->save($user)) {
            return $this->response->withType('application/json')->withStringBody(json_encode(['message' => 'User registered']));
        }
        // 🔥 Debug pour afficher les erreurs exactes
        debug($user->getErrors());
        die(); // Stoppe l'exécution pour afficher les erreurs
        return $this->response->withStatus(400)->withStringBody(json_encode(['error' => 'Registration failed']));
    }

}
