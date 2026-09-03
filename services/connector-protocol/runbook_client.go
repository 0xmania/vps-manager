package connectorprotocol

import "context"

func (c *Client) PreviewRunbook(ctx context.Context, request RunbookPreviewRequest) (RunbookPreviewResponse, error) {
	var response RunbookPreviewResponse
	request.ProtocolVersion = ProtocolVersion
	err := c.post(ctx, RunbookPreviewPath, request, &response)
	return response, err
}

func (c *Client) ExecuteRunbook(ctx context.Context, request RunbookExecuteRequest) (RunbookExecuteResponse, error) {
	var response RunbookExecuteResponse
	request.ProtocolVersion = ProtocolVersion
	err := c.post(ctx, RunbookExecutePath, request, &response)
	return response, err
}
