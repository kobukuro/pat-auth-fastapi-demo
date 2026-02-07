"""
Tests for FCS file download endpoint.

This module tests the FCS file download functionality, including:
- Public file downloads
- Private file access control
- Permission checks
- Error handling
"""
import pytest
from fastapi import status

from tests.api.test_fcs import _create_pat, _get_jwt_with_email, _upload_fcs_file_and_wait


def test_download_public_file_with_fcs_read(client, db):
    """Download public file with fcs:read scope."""
    # Upload public file
    jwt = _get_jwt_with_email(client, "user@example.com")
    pat_write = _create_pat(client, jwt, ["fcs:write"])
    file_id = _upload_fcs_file_and_wait(client, pat_write, "test.fcs", is_public=True)

    # Download with fcs:read PAT
    pat_read = _create_pat(client, jwt, ["fcs:read"])
    response = client.get(
        f"/api/v1/fcs/files/{file_id}/download",
        headers={"Authorization": f"Bearer {pat_read}"}
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["content-type"] == "application/octet-stream"
    assert "attachment" in response.headers["content-disposition"]


def test_download_private_file_owner_can_access(client, db):
    """Owner can download their private file."""
    jwt = _get_jwt_with_email(client, "user@example.com")
    pat_write = _create_pat(client, jwt, ["fcs:write"])
    file_id = _upload_fcs_file_and_wait(client, pat_write, "test.fcs", is_public=False)

    # Owner can download
    pat_read = _create_pat(client, jwt, ["fcs:read"])
    response = client.get(
        f"/api/v1/fcs/files/{file_id}/download",
        headers={"Authorization": f"Bearer {pat_read}"}
    )

    assert response.status_code == status.HTTP_200_OK


def test_download_private_file_non_owner_denied_403(client, db):
    """Non-owner gets 403 for private files."""
    # User1: Upload private file
    jwt1 = _get_jwt_with_email(client, "user1@example.com")
    pat1_write = _create_pat(client, jwt1, ["fcs:write"])
    file_id = _upload_fcs_file_and_wait(client, pat1_write, "test.fcs", is_public=False)

    # User2: Try to download (should be denied)
    jwt2 = _get_jwt_with_email(client, "user2@example.com")
    pat2_read = _create_pat(client, jwt2, ["fcs:read"])
    response = client.get(
        f"/api/v1/fcs/files/{file_id}/download",
        headers={"Authorization": f"Bearer {pat2_read}"}
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    # Check error response - may be wrapped in different format
    resp_data = response.json()
    # Could be {"detail": {"message": "..."} or {"detail": "..."}
    if "detail" in resp_data:
        if isinstance(resp_data["detail"], dict):
            assert resp_data["detail"]["message"] == "Private file - access denied"
        else:
            assert "Private file - access denied" in resp_data["detail"]


def test_download_invalid_file_id_returns_404(client, db):
    """Non-existent file_id returns 404."""
    jwt = _get_jwt_with_email(client, "user@example.com")
    pat_read = _create_pat(client, jwt, ["fcs:read"])

    response = client.get(
        "/api/v1/fcs/files/invalid123id/download",
        headers={"Authorization": f"Bearer {pat_read}"}
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_download_without_fcs_read_scope_returns_403(client, db):
    """User without fcs:read scope gets 403."""
    # First user: Upload with fcs:write
    jwt1 = _get_jwt_with_email(client, "user1@example.com")
    pat1_write = _create_pat(client, jwt1, ["fcs:write"])
    file_id = _upload_fcs_file_and_wait(client, pat1_write, "test.fcs", is_public=True)

    # Second user: Try download with workspaces:read (no fcs scope)
    jwt2 = _get_jwt_with_email(client, "user2@example.com")
    pat2_workspaces = _create_pat(client, jwt2, ["workspaces:read"])
    response = client.get(
        f"/api/v1/fcs/files/{file_id}/download",
        headers={"Authorization": f"Bearer {pat2_workspaces}"}
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_completed_task_includes_download_url(client, db):
    """Completed upload task returns download_url."""
    jwt = _get_jwt_with_email(client, "user@example.com")
    pat_write = _create_pat(client, jwt, ["fcs:write"])
    pat_analyze = _create_pat(client, jwt, ["fcs:write", "fcs:analyze"])

    # Upload file using the helper function
    file_id = _upload_fcs_file_and_wait(client, pat_write, "test.fcs", is_public=True)

    # The helper already waits for completion, but let's verify the task response
    # We need to get a task_id to check the response. Since the helper returns file_id,
    # we'll upload another file to capture the task_id.
    import os
    import time
    from io import BytesIO

    sample_fcs_path = "app/data/sample.fcs"
    file_size = os.path.getsize(sample_fcs_path)
    chunk_size = 5 * 1024 * 1024  # 5MB

    # 1. Initialize chunked upload
    init_response = client.post(
        "/api/v1/fcs/upload",
        headers={"Authorization": f"Bearer {pat_write}"},
        data={
            "filename": "test2.fcs",
            "file_size": file_size,
            "chunk_size": chunk_size,
            "is_public": True,
        },
    )
    assert init_response.status_code == 201
    task_id = init_response.json()["data"]["task_id"]
    total_chunks = init_response.json()["data"]["total_chunks"]

    # 2. Upload all chunks
    with open(sample_fcs_path, "rb") as f:
        for chunk_num in range(total_chunks):
            chunk_data = f.read(chunk_size)
            chunk_file = BytesIO(chunk_data)

            response = client.post(
                "/api/v1/fcs/upload/chunk",
                headers={"Authorization": f"Bearer {pat_write}"},
                data={
                    "task_id": task_id,
                    "chunk_number": chunk_num,
                },
                files={"chunk": (f"chunk_{chunk_num}.dat", chunk_file, "application/octet-stream")},
            )
            assert response.status_code == 202

    # 3. Wait for upload completion
    for _ in range(20):
        response = client.get(
            f"/api/v1/fcs/tasks/{task_id}",
            headers={"Authorization": f"Bearer {pat_analyze}"}
        )
        assert response.status_code == 200
        data = response.json()["data"]
        if data["status"] == "completed":
            break
        time.sleep(0.5)
    else:
        pytest.fail("Upload did not complete in time")

    # 4. Verify download_url is present
    result = response.json()["data"]["result"]
    assert "download_url" in result, f"download_url missing from result: {result}"
    assert "/download" in result["download_url"]
    assert result["download_url"] == f"/api/v1/fcs/files/{result['file_id']}/download"
