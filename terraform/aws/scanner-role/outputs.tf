output "scanner_role_arn" {
  description = "Set as AWS_SCANNER_ROLE_ARN for the dashboard."
  value       = aws_iam_role.scanner.arn
}
