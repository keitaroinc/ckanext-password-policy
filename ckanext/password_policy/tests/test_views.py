# encoding: utf-8


class LoginTestCase:
    def test_login_success(self, app):

        res = app.post_json("/login", {"username": "admin", "password": "secret"})
        assert res.status_code == 200
        assert res.json["success"] is True

    def test_login_failure(self, app):
        res = app.post_json(
            "/login", {"username": "user", "password": "wrong"}, expect_errors=True
        )
        assert res.status_code == 401
        assert res.json["success"] is False
