<?php

class AuthAAI extends AuthPluginBase {

	protected $storage = 'DbStorage';
	static protected $description = 'Shibboleth authentication';
	static protected $name = 'AuthAAI';
	public $atributi = '';
	public $mail = '';
	public $displayName = '';
	protected $settings = array(
			'authsource' => array(
				'type' => 'string',
				'label' => 'Auth source'
				),
			'permission_create_survey' => array(
				'type' => 'checkbox',
				'label' => 'Permission create survey'
				)
			);

	public function init() {
		$this->subscribe('beforeLogin');
		$this->subscribe('newUserSession');
	}

	public function beforeLogin() {
		$authsource = $this->get('authsource');
		// temporary disable Yii autoloader
		spl_autoload_unregister(array('YiiBase', 'autoload'));

		// create 3rd-party object

		// enable Yii autoloader
		spl_autoload_register(array('YiiBase', 'autoload'));

		if (isset($_SERVER['eppn'])) {
			$this->setUsername($_SERVER['nmec']);
			$this->displayName = $_SERVER['cn'];
			$mail = $_SERVER['mail'];
			if (strpos($mail,';') !== false) {
				$mail = explode(";", $mail);
				$mail = $mail[0];
			}
			$this->mail = $mail;
			$this->setAuthPlugin();

		} 

	}

	public function newUserSession() {

		$sUser = $this->getUserName();
		$oUser = $this->api->getUserByName($sUser);

		if (is_null($oUser)) {

			if (isset($_SERVER['eppn'])) {

				// Create new user
				$oUser = new User;
				$oUser->users_name = $sUser;
				$oUser->password = hash('sha256', createPassword());
				$oUser->full_name = $this->displayName;
				$oUser->parent_id = 1;
				$oUser->lang = 'auto';
				$oUser->email = $this->mail;

				if ($oUser->save()) {
					if ($this->get('permission_create_survey', null, null, false)) {
						$data = array(
								'entity_id' => 0,
								'entity' => 'global',
								'uid' => $oUser->uid,
								'permission' => 'surveys',
								'create_p' => 1,
								'read_p' => 1,
								'update_p' => 1,
								'delete_p' => 1,
								'import_p' => 1,
								'export_p' => 1
							     );

						$permission = new Permission;
						foreach ($data as $k => $v)
							$permission->$k = $v;
						$permission->save();
					}
					$this->setAuthSuccess($oUser);
					return;
				} else {
					$this->setAuthFailure(self::ERROR_USERNAME_INVALID);
					return;
				}
				return;
			}
		} else {


			$this->setAuthPlugin();
			$this->setAuthSuccess($oUser);

			return;
		}
	}
}
